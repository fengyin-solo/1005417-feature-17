import { MODULE_BY_KEY } from '@/data/modules'
import { allRows, listRows, resetRows, saveRows } from '@/data/local-store'
import {
  DISTANCE_LIMIT,
  POPULATION_LIMIT,
  THREAT_STATUS,
  THREAT_TYPE_FIELD,
  THREAT_TYPES,
} from '@/data/threat-options'
import type {
  ActionResult,
  BlockedCondition,
  EntryRow,
  FieldError,
  ListFilters,
  ModuleMeta,
  OverviewResult,
  PageResult,
  RangeFilter,
  SaveResult,
  ThreatDraft,
} from '@/data/types'

// 会写进数据的「往回走」动作：命中就把这条记录标成异常态，看板上能一眼看出来。
const NEGATIVE_ACTIONS = ['撤销', '作废', '拒绝', '驳回', '停用', '忽略', '下线', '回滚']

// 连续点两次提交只记一次：这个时间窗内的相同动作视为重复提交。
const RESUBMIT_WINDOW_MS = 1000
const recentActions = new Map<string, number>()

export function moduleMeta(key: string): ModuleMeta {
  const meta = MODULE_BY_KEY.get(key)
  if (!meta) {
    throw new Error(`没有登记名为 ${key} 的业务模块`)
  }
  return meta
}

function toNumber(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : null
  }
  const text = String(value ?? '').trim()
  if (text === '') {
    return null
  }
  const parsed = Number(text)
  return Number.isFinite(parsed) ? parsed : null
}

function isRangeFilter(value: unknown): value is RangeFilter {
  return typeof value === 'object' && value !== null && ('min' in value || 'max' in value)
}

type RangeBound = { value: number } | { error: string }

function parseBound(
  field: string,
  raw: string | undefined,
  edge: 'min' | 'max',
  kind: RangeFilter['kind'],
): RangeBound | null {
  const text = (raw ?? '').trim()
  if (text === '') {
    return null
  }
  const value = toNumber(text)
  if (value === null) {
    return { error: `「${field}」${edge === 'min' ? '下限' : '上限'}填的不是数字（${text}），条件无效` }
  }
  if (kind === 'distance') {
    if (value < 0) {
      return { error: `「${field}」${edge === 'min' ? '下限' : '上限'}不能为负数（${text}米），按无效值退回` }
    }
    if (value > DISTANCE_LIMIT) {
      return { error: `「${field}」${edge === 'min' ? '下限' : '上限'}${text}米超出合理范围 0~${DISTANCE_LIMIT}米，按无效值退回` }
    }
  } else if (kind === 'count') {
    if (value < 0) {
      return { error: `「${field}」${edge === 'min' ? '下限' : '上限'}不能为负数（${text}人），条件无效` }
    }
    if (!Number.isInteger(value)) {
      return { error: `「${field}」${edge === 'min' ? '下限' : '上限'}必须是整数（${text}），条件无效` }
    }
    if (value > POPULATION_LIMIT) {
      return { error: `「${field}」${edge === 'min' ? '下限' : '上限'}${text}人超出上限 ${POPULATION_LIMIT}，条件无效` }
    }
  }
  return { value }
}

function applyRangeFilter(
  rows: EntryRow[],
  field: string,
  filter: RangeFilter,
  blocked: BlockedCondition[],
): EntryRow[] {
  const label = filter.kind === 'distance' ? `${field}（米）` : field
  const minBound = parseBound(field, filter.min, 'min', filter.kind)
  const maxBound = parseBound(field, filter.max, 'max', filter.kind)

  if (minBound && 'error' in minBound) {
    blocked.push({ field, message: minBound.error })
    return []
  }
  if (maxBound && 'error' in maxBound) {
    blocked.push({ field, message: maxBound.error })
    return []
  }
  const min = minBound && 'value' in minBound ? minBound.value : null
  const max = maxBound && 'value' in maxBound ? maxBound.value : null
  if (min !== null && max !== null && min > max) {
    blocked.push({ field, message: `「${label}」区间反了：下限 ${min} 大于上限 ${max}，请调整` })
    return []
  }

  // 历史记录里数值字段可能是文字样例：无法解析成数字时不参与数值匹配，绝不硬转。
  const matched = rows.filter((row) => {
    const value = toNumber(row[field])
    if (value === null) {
      return false
    }
    if (min !== null && value < min) {
      return false
    }
    if (max !== null && value > max) {
      return false
    }
    return true
  })

  if (min === null && max === null) {
    return rows
  }
  const scope = min !== null && max !== null ? `${min}~${max}` : min !== null ? `≥${min}` : `≤${max}`
  if (matched.length === 0) {
    blocked.push({ field, message: `「${label}」卡在 ${scope} 这一项：没有落在该区间内的记录` })
  }
  return matched
}

export function queryRows(rows: EntryRow[], filters: ListFilters): { items: EntryRow[]; blocked: BlockedCondition[] } {
  const pairs = Object.entries(filters).filter(([, value]) => {
    if (Array.isArray(value)) {
      return value.length > 0
    }
    if (isRangeFilter(value)) {
      return (value.min ?? '').trim() !== '' || (value.max ?? '').trim() !== ''
    }
    return String(value ?? '').trim() !== ''
  })

  const blocked: BlockedCondition[] = []
  if (pairs.length === 0) {
    return { items: rows, blocked }
  }

  let matched = rows
  for (const [field, value] of pairs) {
    if (isRangeFilter(value)) {
      matched = applyRangeFilter(matched, field, value, blocked)
      if (blocked.length > 0 && matched.length === 0) {
        return { items: [], blocked }
      }
      continue
    }

    if (Array.isArray(value)) {
      const wanted = value.map((item) => item.trim()).filter((item) => item !== '')
      const next = matched.filter((row) => wanted.includes(String(row[field] ?? '').trim()))
      if (next.length === 0) {
        blocked.push({ field, message: `「${field}」卡在多选这一项：没有类型属于 ${wanted.join('、')} 的记录` })
        return { items: [], blocked }
      }
      matched = next
      continue
    }

    const keyword = String(value).trim()
    const next = matched.filter((row) => String(row[field] ?? '').includes(keyword))
    if (next.length === 0) {
      blocked.push({ field, message: `「${field}」卡在关键字「${keyword}」这一项：没有匹配的记录` })
      return { items: [], blocked }
    }
    matched = next
  }

  return { items: matched, blocked }
}

// 兼容旧调用：其它模块仍传 Record<string,string>，走纯文本包含匹配。
export function filterRows(rows: EntryRow[], filters: Record<string, string>): EntryRow[] {
  const pairs = Object.entries(filters).filter(([, value]) => value.trim() !== '')
  if (pairs.length === 0) {
    return rows
  }
  return rows.filter((row) =>
    pairs.every(([field, value]) => String(row[field] ?? '').includes(value.trim())),
  )
}

export function listEntries(key: string, filters: ListFilters | Record<string, string> = {}): PageResult {
  const { items, blocked } = queryRows(listRows(key), filters as ListFilters)
  return { items, total: items.length, page: 1, size: items.length, blocked }
}

function isDuplicateSubmit(token: string): boolean {
  const now = Date.now()
  const last = recentActions.get(token)
  return last !== undefined && now - last < RESUBMIT_WINDOW_MS
}

// 只有真正落了数据的提交才记账，被挡回/校验不过的尝试不影响后续正常提交。
function markSubmitted(token: string): void {
  recentActions.set(token, Date.now())
}

/** 受威胁对象逐格流转：只允许走到当前环节的下一格，跳格、回退都挡回。 */
function guardStrictFlow(meta: ModuleMeta, current: string, target: string): string | null {
  const order = meta.statuses
  const currentIndex = order.indexOf(current)
  const targetIndex = order.indexOf(target)
  if (currentIndex < 0) {
    return `当前状态「${current}」不在规定环节里，不能直接流转，请先核对记录`
  }
  if (targetIndex < 0) {
    return `目标状态「${target}」不在规定环节里`
  }
  if (targetIndex <= currentIndex) {
    return `环节只能按 ${order.join('→')} 的次序流转，已在「${current}」，不能回到「${target}」`
  }
  if (targetIndex > currentIndex + 1) {
    return `环节只能按 ${order.join('→')} 的次序逐格流转，不能从「${current}」直接跳到「${target}」，请先办理「${order[currentIndex + 1]}」`
  }
  return null
}

/** 转移确认后，在裂缝观测清单里补一条转移核对项；已同步过的不重复补。 */
function syncTransferCheck(source: EntryRow): void {
  const crackRows = [...listRows('crack')]
  const code = String(source['对象编号'] ?? '').trim()
  const already = crackRows.some((row) => String(row['裂缝编号'] ?? '') === `XFER-${code}`)
  if (already) {
    return
  }
  const nextId = crackRows.reduce((max, row) => Math.max(max, Number(row.id) || 0), 0) + 1
  const today = new Date().toISOString().slice(0, 10)
  crackRows.push({
    id: nextId,
    status: '待观测',
    pending: true,
    abnormal: false,
    裂缝编号: `XFER-${code}`,
    所属隐患点: source['所属隐患点'] ?? '',
    // 两处读到的对象类型必须一致：直接搬运受威胁对象上的原值，不做转换。
    [THREAT_TYPE_FIELD]: source[THREAT_TYPE_FIELD] ?? '',
    裂缝走向: `转移核对：${source['对象名称'] ?? ''}`,
    本期宽度: '待核对',
    累计变宽: '待核对',
    观测日期: today,
    观测人: source['联系人'] ?? '',
    裂缝状态: '转移核对',
  })
  saveRows('crack', crackRows)
}

export function runAction(key: string, id: number, action: string): ActionResult {
  const meta = moduleMeta(key)
  const target = meta.actionTargets[action]
  if (!target) {
    return { ok: false, message: `${meta.entity}没有登记「${action}」这个动作` }
  }
  const rows = listRows(key)
  const index = rows.findIndex((row) => Number(row.id) === id)
  if (index < 0) {
    return { ok: false, message: `没有找到编号为 ${id} 的${meta.entity}` }
  }
  const current = String(rows[index].status)

  // 连续点两次提交只记一次：时间窗内同一对象的同一动作直接吞掉（即便第一次已把状态改走），不重复落数据。
  const token = `${key}:${id}:${action}`
  if (isDuplicateSubmit(token)) {
    return { ok: true, duplicated: true, message: `${meta.entity}已${action}，连续提交已忽略，只记一次（当前状态「${current}」）` }
  }

  if (current === target) {
    return { ok: false, message: `${meta.entity}已经是「${target}」，不用重复操作` }
  }
  if (meta.strictFlow) {
    const blocked = guardStrictFlow(meta, current, target)
    if (blocked) {
      return { ok: false, message: blocked }
    }
  }
  const lastStatus = meta.statuses[meta.statuses.length - 1]
  const updated: EntryRow = {
    ...rows[index],
    status: target,
    pending: target !== lastStatus,
    abnormal: NEGATIVE_ACTIONS.some((verb) => action.startsWith(verb)),
  }
  const next = [...rows]
  next[index] = updated
  saveRows(key, next)
  markSubmitted(token)
  if (key === 'threat' && target === THREAT_STATUS.transferred) {
    syncTransferCheck(updated)
  }
  return { ok: true, message: `${meta.entity}已${action}，当前状态「${target}」` }
}

function validateThreatDraft(draft: ThreatDraft, rows: EntryRow[]): FieldError[] {
  const errors: FieldError[] = []
  const text = (value: string) => value.trim()

  const required: [keyof ThreatDraft, string][] = [
    ['对象编号', '对象编号'],
    ['所属隐患点', '所属隐患点'],
    [THREAT_TYPE_FIELD, THREAT_TYPE_FIELD],
    ['对象名称', '对象名称'],
    ['涉及人数', '涉及人数'],
    ['最近距离', '最近距离'],
  ]
  for (const [field, label] of required) {
    if (text(draft[field]) === '') {
      errors.push({ field, message: `「${label}」不能为空` })
    }
  }

  const code = text(draft['对象编号'])
  if (code !== '') {
    if (!/^[A-Za-z0-9-]+$/.test(code)) {
      errors.push({ field: '对象编号', message: '「对象编号」只能包含字母、数字和连字符' })
    } else if (rows.some((row) => String(row['对象编号'] ?? '').trim() === code)) {
      errors.push({ field: '对象编号', message: `「对象编号」${code} 已存在，不能重复登记` })
    }
  }

  const type = text(draft[THREAT_TYPE_FIELD])
  if (type !== '' && !THREAT_TYPES.includes(type as (typeof THREAT_TYPES)[number])) {
    errors.push({ field: THREAT_TYPE_FIELD, message: `「${THREAT_TYPE_FIELD}」必须从字典里选择：${THREAT_TYPES.join('、')}` })
  }

  const people = toNumber(draft['涉及人数'])
  if (text(draft['涉及人数']) !== '') {
    if (people === null) {
      errors.push({ field: '涉及人数', message: '「涉及人数」填的不是数字，按无效值退回' })
    } else if (people < 0) {
      errors.push({ field: '涉及人数', message: '「涉及人数」不能为负数，按无效值退回' })
    } else if (!Number.isInteger(people)) {
      errors.push({ field: '涉及人数', message: '「涉及人数」必须是整数' })
    } else if (people > POPULATION_LIMIT) {
      errors.push({ field: '涉及人数', message: `「涉及人数」不能超过 ${POPULATION_LIMIT} 人` })
    }
  }

  const distance = toNumber(draft['最近距离'])
  if (text(draft['最近距离']) !== '') {
    if (distance === null) {
      errors.push({ field: '最近距离', message: '「最近距离」填的不是数字，按无效值退回' })
    } else if (distance < 0) {
      errors.push({ field: '最近距离', message: '「最近距离」不能为负数，按无效值退回' })
    } else if (distance > DISTANCE_LIMIT) {
      errors.push({ field: '最近距离', message: `「最近距离」超出合理范围 0~${DISTANCE_LIMIT}米，按无效值退回` })
    }
  }

  return errors
}

/** 登记受威胁对象：校验不过按字段退回，最近距离越界/负数一律不收。 */
export function registerThreat(draft: ThreatDraft): SaveResult {
  const rows = listRows('threat')

  // 先做不依赖库存数据的格式校验：格式被退回的提交不参与连点判重，改好后还能正常提交。
  const formatErrors = validateThreatDraft(draft, [])
  const code = draft['对象编号'].trim()
  const codeOk = !formatErrors.some((error) => error.field === '对象编号')

  // 连点两次提交只记一次：格式合法时先按编号做时间窗判重，
  // 放在「编号已存在」校验之前，否则第一次落库后第二次会先撞重复编号。
  const token = codeOk ? `threat:create:${code}` : null
  if (token && isDuplicateSubmit(token)) {
    return { ok: true, duplicated: true, message: `受威胁对象 ${code} 的登记正在处理，连续提交已忽略，只记一次` }
  }

  const errors = validateThreatDraft(draft, rows)
  if (errors.length > 0) {
    return { ok: false, message: `登记被退回，有 ${errors.length} 项需要修改`, errors }
  }

  const nextId = rows.reduce((max, row) => Math.max(max, Number(row.id) || 0), 0) + 1
  const row: EntryRow = {
    id: nextId,
    status: THREAT_STATUS.pending,
    pending: true,
    abnormal: false,
    对象编号: code,
    所属隐患点: draft['所属隐患点'].trim(),
    [THREAT_TYPE_FIELD]: draft[THREAT_TYPE_FIELD].trim(),
    对象名称: draft['对象名称'].trim(),
    涉及人数: Number(draft['涉及人数']),
    最近距离: Number(draft['最近距离']),
    联系人: draft['联系人'].trim(),
    对象状态: THREAT_STATUS.pending,
  }
  saveRows('threat', [...rows, row])
  if (token) {
    markSubmitted(token)
  }
  return { ok: true, message: `受威胁对象 ${code} 已登记，当前状态「${THREAT_STATUS.pending}」` }
}

/** 受威胁对象看板统计：始终基于全量数据算，不受当前查询条件影响。 */
export function threatSummary(): { registered: number; transferred: number; people: number } {
  const rows = listRows('threat')
  return {
    registered: rows.filter((row) => String(row.status) !== THREAT_STATUS.pending).length,
    transferred: rows.filter((row) => String(row.status) === THREAT_STATUS.transferred).length,
    people: rows.reduce((sum, row) => {
      const value = toNumber(row['涉及人数'])
      return sum + (value !== null && value >= 0 ? value : 0)
    }, 0),
  }
}

export function resetModule(key: string): PageResult {
  resetRows(key)
  return listEntries(key)
}

export function exportEntries(key: string): { filename: string; content: string } {
  const meta = moduleMeta(key)
  const header = ['编号', ...meta.fields, '当前状态']
  const lines = [header.join(',')]
  for (const row of listRows(key)) {
    lines.push([row.id, ...meta.fields.map((field) => row[field] ?? ''), row.status].join(','))
  }
  return { filename: `${meta.name}-清单.csv`, content: `\uFEFF${lines.join('\n')}` }
}

export function downloadEntries(key: string): void {
  const { filename, content } = exportEntries(key)
  const blob = new Blob([content], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

export function loadOverview(): OverviewResult {
  const rows = allRows()
  const modules = [...MODULE_BY_KEY.values()].map((meta) => {
    const entries = rows[meta.key] ?? []
    return {
      name: meta.name,
      created: entries.length,
      pending: entries.filter((row) => row.pending).length,
      abnormal: entries.filter((row) => row.abnormal).length,
    }
  })
  const cards = [
    { label: '业务模块', value: modules.length },
    { label: '登记总量', value: modules.reduce((sum, item) => sum + item.created, 0) },
    { label: '待处理', value: modules.reduce((sum, item) => sum + item.pending, 0) },
    { label: '异常量', value: modules.reduce((sum, item) => sum + item.abnormal, 0) },
  ]
  return { cards, modules }
}
