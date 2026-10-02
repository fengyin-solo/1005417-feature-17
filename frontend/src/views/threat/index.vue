<template>
  <section class="page" data-module="threat">
    <header class="page-head">
      <div>
        <h2>受威胁对象管理</h2>
        <p class="page-desc">维护受威胁对象，围绕对象编号、所属隐患点、对象类型、对象名称做登记、筛选与状态流转。</p>
      </div>
      <div class="page-actions">
        <button class="btn primary" type="button" @click="openCreate">登记受威胁对象</button>
        <button class="btn" type="button" @click="exportRows">导出受威胁对象清单</button>
      </div>
    </header>

    <div class="stat-row">
      <article v-for="item in stats" :key="item.label" class="stat-card">
        <span class="stat-label">{{ item.label }}</span>
        <strong class="stat-value">{{ item.value }}</strong>
      </article>
    </div>

    <p class="status-legend">
      <span v-for="item in statusSummary" :key="item.status" class="legend-item">
        {{ item.status }}：{{ item.count }}
      </span>
    </p>

    <form class="filter-bar" @submit.prevent="reload">
      <label class="filter-item">
        <span>对象编号</span>
        <input v-model="codeFilter" placeholder="按对象编号检索" />
      </label>
      <fieldset class="filter-item filter-checks">
        <legend>对象类型（可多选）</legend>
        <label v-for="type in typeOptions" :key="type" class="check-pill">
          <input v-model="typeSelection" type="checkbox" :value="type" />
          {{ type }}
        </label>
      </fieldset>
      <div class="filter-item">
        <span>最近距离区间（米）</span>
        <div class="range-inputs">
          <input v-model="distanceFilter.min" type="number" min="0" :max="distanceLimit" placeholder="最小" />
          <em>至</em>
          <input v-model="distanceFilter.max" type="number" min="0" :max="distanceLimit" placeholder="最大" />
        </div>
      </div>
      <div class="filter-item">
        <span>涉及人数上下限（人）</span>
        <div class="range-inputs">
          <input v-model="peopleFilter.min" type="number" min="0" step="1" placeholder="下限" />
          <em>至</em>
          <input v-model="peopleFilter.max" type="number" min="0" step="1" placeholder="上限" />
        </div>
      </div>
      <button class="btn" type="submit">查询</button>
      <button class="btn ghost" type="button" @click="resetFilters">重置条件</button>
    </form>

    <ul v-if="blockedItems.length" class="blocked-list">
      <li v-for="(item, index) in blockedItems" :key="`${item.field}-${index}`" class="error-text">
        {{ item.message }}
      </li>
    </ul>

    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in columns" :key="column">{{ column }}</th>
          <th>当前状态</th>
          <th>可执行动作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)">
          <td v-for="column in columns" :key="column">{{ formatCell(row, column) }}</td>
          <td>{{ row.status }}</td>
          <td class="row-actions">
            <button
              v-for="action in availableActions(row)"
              :key="action"
              class="link"
              type="button"
              @click="runAction(action, row)"
            >
              {{ action }}
            </button>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="columns.length + 2" class="empty-state">
            {{ blockedItems.length ? '没有记录通过当前条件，请看上方卡点说明' : '暂无受威胁对象数据，可先登记受威胁对象' }}
          </td>
        </tr>
      </tbody>
    </table>

    <footer class="page-foot">
      <span>共 {{ total }} 条受威胁对象记录</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>

    <div v-if="creating" class="modal-mask" @click.self="closeCreate">
      <form class="modal-card" @submit.prevent="submitCreate">
        <header class="modal-head">
          <h3>登记受威胁对象</h3>
          <button class="btn ghost" type="button" @click="closeCreate">关闭</button>
        </header>
        <div class="form-grid">
          <label class="form-field">
            <span>对象编号 *</span>
            <input v-model="draft['对象编号']" placeholder="如 THRE-0010" />
          </label>
          <label class="form-field">
            <span>所属隐患点 *</span>
            <input v-model="draft['所属隐患点']" placeholder="所属隐患点名称或编号" />
          </label>
          <label class="form-field">
            <span>对象类型 *</span>
            <select v-model="draft['对象类型']">
              <option value="" disabled>请选择对象类型</option>
              <option v-for="type in typeOptions" :key="type" :value="type">{{ type }}</option>
            </select>
          </label>
          <label class="form-field">
            <span>对象名称 *</span>
            <input v-model="draft['对象名称']" placeholder="如 某某村三组" />
          </label>
          <label class="form-field">
            <span>涉及人数 *（整数）</span>
            <input v-model="draft['涉及人数']" type="number" min="0" step="1" placeholder="人" />
          </label>
          <label class="form-field">
            <span>最近距离 *（米，0~{{ distanceLimit }}）</span>
            <input v-model="draft['最近距离']" type="number" min="0" :max="distanceLimit" step="0.1" placeholder="米" />
          </label>
          <label class="form-field">
            <span>联系人</span>
            <input v-model="draft['联系人']" placeholder="联系人姓名" />
          </label>
        </div>
        <ul v-if="fieldErrors.length" class="blocked-list">
          <li v-for="error in fieldErrors" :key="error.field" class="error-text">{{ error.message }}</li>
        </ul>
        <footer class="modal-foot">
          <button class="btn primary" type="submit" :disabled="submitting">{{ submitting ? '提交中…' : '提交登记' }}</button>
          <button class="btn ghost" type="button" @click="closeCreate">取消</button>
        </footer>
      </form>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import {
  downloadEntries,
  listEntries,
  moduleMeta,
  registerThreat,
  runAction as applyAction,
  threatSummary,
} from '@/api/local-service'
import { DISTANCE_LIMIT, THREAT_TYPES } from '@/data/threat-options'
import type { BlockedCondition, EntryRow, ListFilters, ThreatDraft } from '@/data/types'

const meta = moduleMeta('threat')
const columns = ["对象编号", "所属隐患点", "对象类型", "对象名称", "涉及人数", "最近距离", "联系人", "对象状态"]
const statuses = ["待登记", "已登记", "已转移", "已解除"]
const actionsByStatus: Record<string, string[]> = {
  待登记: ["提交登记"],
  已登记: ["确认转移"],
  已转移: ["登记解除"],
  已解除: [],
}

const allCache = ref<EntryRow[]>([])
// 历史记录的对象类型五花八门（样例文本照原样留着），筛选项里也要能选到。
const typeOptions = computed(() => {
  const used = new Set<string>([...THREAT_TYPES])
  for (const row of allCache.value) {
    const value = String(row['对象类型'] ?? '').trim()
    if (value !== '') {
      used.add(value)
    }
  }
  return [...used]
})
const distanceLimit = DISTANCE_LIMIT

const rows = ref<EntryRow[]>([])
const total = ref(0)
const errorMessage = ref('')
const blockedItems = ref<BlockedCondition[]>([])

const codeFilter = ref('')
const typeSelection = ref<string[]>([])
const distanceFilter = reactive({ min: '', max: '' })
const peopleFilter = reactive({ min: '', max: '' })

const creating = ref(false)
const submitting = ref(false)
const fieldErrors = ref<{ field: string; message: string }[]>([])
const emptyDraft = (): ThreatDraft => ({
  对象编号: '',
  所属隐患点: '',
  对象类型: '',
  对象名称: '',
  涉及人数: '',
  最近距离: '',
  联系人: '',
})
const draft = reactive<ThreatDraft>(emptyDraft())

const stats = ref([
  { label: '已登记对象', value: 0 },
  { label: '已转移对象', value: 0 },
  { label: '涉及人数合计', value: 0 },
])
const statusSummary = computed(() =>
  statuses.map((status: string) => ({
    status,
    count: allCache.value.filter((row) => String(row.status) === status).length,
  })),
)

function buildFilters(): ListFilters {
  return {
    对象编号: codeFilter.value.trim(),
    对象类型: [...typeSelection.value],
    最近距离: { kind: 'distance', min: distanceFilter.min.trim(), max: distanceFilter.max.trim() },
    涉及人数: { kind: 'count', min: peopleFilter.min.trim(), max: peopleFilter.max.trim() },
  }
}

// 环节只能按 待登记→已登记→已转移→已解除 逐格走，列表里只露出下一格动作，挡回的提示交给服务层兜底。
function availableActions(row: EntryRow): string[] {
  return actionsByStatus[String(row.status)] ?? []
}

function formatCell(row: EntryRow, column: string): string | number {
  const value = row[column]
  if (column === '最近距离' && typeof value === 'number') {
    return `${value} 米`
  }
  return (value ?? '—') as string | number
}

function resetFilters() {
  codeFilter.value = ''
  typeSelection.value = []
  distanceFilter.min = ''
  distanceFilter.max = ''
  peopleFilter.min = ''
  peopleFilter.max = ''
  reload()
}

function exportRows() {
  downloadEntries(meta.key)
}

function openCreate() {
  errorMessage.value = ''
  fieldErrors.value = []
  Object.assign(draft, emptyDraft())
  creating.value = true
}

function closeCreate() {
  creating.value = false
  submitting.value = false
}

function submitCreate() {
  if (submitting.value) {
    return
  }
  fieldErrors.value = []
  submitting.value = true
  // 连续点两次提交只记一次：按钮即时置灰，服务层再按对象编号做时间窗去重双保险。
  try {
    const result = registerThreat({ ...draft })
    if (!result.ok) {
      fieldErrors.value = result.errors ?? []
      errorMessage.value = result.errors?.length ? '' : result.message
      return
    }
    errorMessage.value = result.duplicated ? result.message : ''
    closeCreate()
    reload()
  } finally {
    submitting.value = false
  }
}

function runAction(action: string, row: EntryRow) {
  errorMessage.value = ''
  const result = applyAction(meta.key, Number(row.id), action)
  if (result.duplicated) {
    errorMessage.value = result.message
    return
  }
  if (!result.ok) {
    errorMessage.value = result.message
    return
  }
  reload()
}

function refreshStats() {
  const summary = threatSummary()
  stats.value = [
    { label: '已登记对象', value: summary.registered },
    { label: '已转移对象', value: summary.transferred },
    { label: '涉及人数合计', value: summary.people },
  ]
}

function reload() {
  errorMessage.value = ''
  try {
    // 统计与状态图例始终读全量；条件筛选只作用在表格。
    allCache.value = listEntries(meta.key).items
    const payload = listEntries(meta.key, buildFilters())
    rows.value = payload.items
    total.value = payload.total
    blockedItems.value = payload.blocked ?? []
    refreshStats()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '受威胁对象列表读取失败'
  }
}

onMounted(reload)
</script>
