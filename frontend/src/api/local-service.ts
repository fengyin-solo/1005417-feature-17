import { MODULE_BY_KEY } from '@/data/modules'
import { allRows, listRows, resetRows, saveRows } from '@/data/local-store'
import type {
  ActionResult,
  EntryRow,
  ModuleMeta,
  OverviewResult,
  PageResult,
  ThreatQuery,
  ThreatQueryResult,
} from '@/data/types'

// 会写进数据的「往回走」动作：命中就把这条记录标成异常态，看板上能一眼看出来。
const NEGATIVE_ACTIONS = ['撤销', '作废', '拒绝', '驳回', '停用', '忽略', '下线', '回滚']

// 受威胁对象的常用对象类型。历史记录里的类型不改动、不合并，筛选时与这份清单取并集。
export const THREAT_OBJECT_TYPES = ['民居', '学校', '医院', '厂房', '村道', '农田', '其他']

// 最近距离的有效范围（米）：填成负数或超出上限都按无效值退回。
export const THREAT_DISTANCE_MAX = 10000

export function moduleMeta(key: string): ModuleMeta {
  const meta = MODULE_BY_KEY.get(key)
  if (!meta) {
    throw new Error(`没有登记名为 ${key} 的业务模块`)
  }
  return meta
}

export function filterRows(rows: EntryRow[], filters: Record<string, string>): EntryRow[] {
  const pairs = Object.entries(filters).filter(([, value]) => value.trim() !== '')
  if (pairs.length === 0) {
    return rows
  }
  return rows.filter((row) =>
    pairs.every(([field, value]) => String(row[field] ?? '').includes(value.trim())),
  )
}

export function listEntries(key: string, filters: Record<string, string> = {}): PageResult {
  const matched = filterRows(listRows(key), filters)
  return { items: matched, total: matched.length, page: 1, size: matched.length }
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
  if (current === target) {
    return { ok: false, message: `${meta.entity}已经是「${target}」，不用重复操作` }
  }
  if (meta.strictOrder) {
    const currentIndex = meta.statuses.indexOf(current)
    const targetIndex = meta.statuses.indexOf(target)
    // 历史数据里可能出现名单之外的状态，那种记录不卡顺序；在名单内的必须逐环流转。
    if (currentIndex >= 0 && targetIndex !== currentIndex + 1) {
      return {
        ok: false,
        message: `${meta.entity}环节只能按「${meta.statuses.join('→')}」次序流转，当前「${current}」不能直接到「${target}」`,
      }
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
  if (key === 'threat' && action === '确认转移') {
    syncTransferCheck(updated)
  }
  return { ok: true, message: `${meta.entity}已${action}，当前状态「${target}」` }
}

// 受威胁对象确认转移后，裂缝观测清单要跟着多一条转移核对项。
// 对象类型原样抄过去，保证两处读到的一致；同一个对象只补一条，重复提交不会重复生成。
function syncTransferCheck(threatRow: EntryRow): void {
  const objectCode = String(threatRow['对象编号'] ?? '')
  const crackRows = listRows('crack')
  const exists = crackRows.some(
    (row) => row['核对项'] === '转移核对' && String(row['关联对象编号'] ?? '') === objectCode,
  )
  if (exists) {
    return
  }
  const nextId = crackRows.reduce((max, row) => Math.max(max, Number(row.id) || 0), 0) + 1
  const checkItem: EntryRow = {
    id: nextId,
    status: '待观测',
    pending: true,
    abnormal: false,
    裂缝编号: `ZY-${objectCode}`,
    所属隐患点: threatRow['所属隐患点'] ?? '—',
    裂缝走向: '转移核对',
    本期宽度: '—',
    累计变宽: '—',
    观测日期: new Date().toISOString().slice(0, 10),
    观测人: '待核对',
    裂缝状态: '转移核对',
    对象类型: threatRow['对象类型'] ?? '—',
    关联对象编号: objectCode,
    核对项: '转移核对',
  }
  saveRows('crack', [...crackRows, checkItem])
}

export function resetModule(key: string): PageResult {
  resetRows(key)
  return listEntries(key)
}

// 对象类型筛选项：常用类型加上数据里实际出现过的类型（历史值原样保留，照样能筛）。
export function threatObjectTypes(): string[] {
  const seen = new Set<string>(THREAT_OBJECT_TYPES)
  for (const row of listRows('threat')) {
    const value = String(row['对象类型'] ?? '').trim()
    if (value !== '') {
      seen.add(value)
    }
  }
  return [...seen]
}

type BoundCheck =
  | { ok: true; value: number | null }
  | { ok: false; message: string }

// 区间端点校验：留空表示不卡这一头；非数字、负数、越界都按无效值退回。
function parseBound(raw: string, label: string, max: number | null): BoundCheck {
  const text = raw.trim()
  if (text === '') {
    return { ok: true, value: null }
  }
  const value = Number(text)
  if (!Number.isFinite(value)) {
    return { ok: false, message: `${label}「${text}」不是有效数字，按无效值退回` }
  }
  if (value < 0) {
    return { ok: false, message: `${label}不能填负数（${text}），按无效值退回` }
  }
  if (max !== null && value > max) {
    return { ok: false, message: `${label}超出有效范围 0~${max}（${text}），按无效值退回` }
  }
  return { ok: true, value }
}

function toNumber(value: unknown): number | null {
  if (typeof value === 'string' && value.trim() === '') {
    return null
  }
  const num = Number(value)
  return Number.isFinite(num) ? num : null
}

// 受威胁对象条件定位：编号模糊、类型多选、最近距离按区间、涉及人数按上下限。
// 查不到记录时逐项回查，告诉调用方卡在哪一项条件上。
export function queryThreatEntries(query: ThreatQuery): ThreatQueryResult {
  const empty: ThreatQueryResult = { items: [], total: 0, page: 1, size: 0, invalid: '', blockers: [] }

  const distanceMin = parseBound(query.最近距离下限, '最近距离下限', THREAT_DISTANCE_MAX)
  if (!distanceMin.ok) {
    return { ...empty, invalid: distanceMin.message }
  }
  const distanceMax = parseBound(query.最近距离上限, '最近距离上限', THREAT_DISTANCE_MAX)
  if (!distanceMax.ok) {
    return { ...empty, invalid: distanceMax.message }
  }
  if (distanceMin.value !== null && distanceMax.value !== null && distanceMin.value > distanceMax.value) {
    return { ...empty, invalid: `最近距离下限（${distanceMin.value}）高于上限（${distanceMax.value}），区间越界，按无效值退回` }
  }
  const peopleMin = parseBound(query.涉及人数下限, '涉及人数下限', null)
  if (!peopleMin.ok) {
    return { ...empty, invalid: peopleMin.message }
  }
  const peopleMax = parseBound(query.涉及人数上限, '涉及人数上限', null)
  if (!peopleMax.ok) {
    return { ...empty, invalid: peopleMax.message }
  }
  if (peopleMin.value !== null && peopleMax.value !== null && peopleMin.value > peopleMax.value) {
    return { ...empty, invalid: `涉及人数下限（${peopleMin.value}）高于上限（${peopleMax.value}），区间越界，按无效值退回` }
  }

  const rows = listRows('threat')
  const conditions: { name: string; test: (row: EntryRow) => boolean }[] = []

  const code = query.对象编号.trim()
  if (code !== '') {
    conditions.push({
      name: `对象编号包含「${code}」`,
      test: (row) => String(row['对象编号'] ?? '').includes(code),
    })
  }
  const types = query.对象类型.filter((item) => item.trim() !== '')
  if (types.length > 0) {
    conditions.push({
      name: `对象类型为「${types.join('、')}」`,
      test: (row) => types.includes(String(row['对象类型'] ?? '')),
    })
  }
  if (distanceMin.value !== null || distanceMax.value !== null) {
    const minText = distanceMin.value ?? 0
    const maxText = distanceMax.value ?? THREAT_DISTANCE_MAX
    conditions.push({
      name: `最近距离在 ${minText}~${maxText} 米`,
      test: (row) => {
        const value = toNumber(row['最近距离'])
        if (value === null) {
          return false
        }
        if (distanceMin.value !== null && value < distanceMin.value) {
          return false
        }
        if (distanceMax.value !== null && value > distanceMax.value) {
          return false
        }
        return true
      },
    })
  }
  if (peopleMin.value !== null || peopleMax.value !== null) {
    const minText = peopleMin.value ?? 0
    const maxText = peopleMax.value ?? '不限'
    conditions.push({
      name: `涉及人数在 ${minText}~${maxText} 人`,
      test: (row) => {
        const value = toNumber(row['涉及人数'])
        if (value === null) {
          return false
        }
        if (peopleMin.value !== null && value < peopleMin.value) {
          return false
        }
        if (peopleMax.value !== null && value > peopleMax.value) {
          return false
        }
        return true
      },
    })
  }

  const matched = rows.filter((row) => conditions.every((condition) => condition.test(row)))
  const blockers: string[] = []
  if (matched.length === 0 && conditions.length > 0) {
    const solo = conditions.map((condition) => ({
      name: condition.name,
      count: rows.filter(condition.test).length,
    }))
    const blocking = solo.filter((item) => item.count === 0)
    if (blocking.length > 0) {
      blockers.push(...blocking.map((item) => `卡在「${item.name}」：单独按这项查也没有任何记录`))
    } else {
      blockers.push(
        `每一项单独都能查到记录（${solo.map((item) => `${item.name} ${item.count} 条`).join('，')}），但没有同时满足全部条件的对象`,
      )
    }
  }
  return { items: matched, total: matched.length, page: 1, size: matched.length, invalid: '', blockers }
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
