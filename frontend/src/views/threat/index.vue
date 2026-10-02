<template>
  <section class="page" data-module="threat">
    <header class="page-head">
      <div>
        <h2>受威胁对象管理</h2>
        <p class="page-desc">维护受威胁对象，对象编号、对象类型、最近距离、涉及人数都能组合定位，状态按待登记→已登记→已转移→已解除逐环流转。</p>
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
        <input v-model="criteria.对象编号" placeholder="按对象编号检索" />
      </label>
      <div class="filter-item">
        <span>最近距离（米）</span>
        <div class="range-inputs">
          <input v-model="criteria.最近距离下限" type="number" min="0" placeholder="下限" />
          <span class="range-sep">~</span>
          <input v-model="criteria.最近距离上限" type="number" min="0" placeholder="上限" />
        </div>
      </div>
      <div class="filter-item">
        <span>涉及人数（人）</span>
        <div class="range-inputs">
          <input v-model="criteria.涉及人数下限" type="number" min="0" placeholder="下限" />
          <span class="range-sep">~</span>
          <input v-model="criteria.涉及人数上限" type="number" min="0" placeholder="上限" />
        </div>
      </div>
      <button class="btn" type="submit">查询</button>
      <button class="btn ghost" type="button" @click="resetFilters">重置条件</button>
      <div class="filter-item type-filter">
        <span>对象类型（可多选）</span>
        <label v-for="item in typeOptions" :key="item" class="type-option">
          <input v-model="criteria.对象类型" type="checkbox" :value="item" />
          {{ item }}
        </label>
      </div>
    </form>

    <p v-if="queryHint" class="query-hint">{{ queryHint }}</p>

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
          <td v-for="column in columns" :key="column">{{ row[column] ?? '—' }}</td>
          <td>{{ row.status }}</td>
          <td class="row-actions">
            <button
              v-for="action in actions"
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
          <td :colspan="columns.length + 2" class="empty-state">暂无受威胁对象数据，可先登记受威胁对象</td>
        </tr>
      </tbody>
    </table>

    <footer class="page-foot">
      <span>共 {{ total }} 条受威胁对象记录</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import {
  downloadEntries,
  moduleMeta,
  queryThreatEntries,
  runAction as applyAction,
  threatObjectTypes,
} from '@/api/local-service'
import type { EntryRow, ThreatQuery } from '@/data/types'

const meta = moduleMeta('threat')
const columns = ["对象编号", "所属隐患点", "对象类型", "对象名称", "涉及人数", "最近距离", "联系人", "对象状态"]
const actions = ["提交登记", "确认转移", "登记解除"]
const statuses = ["待登记", "已登记", "已转移", "已解除"]
const stats = [{"label": "已登记对象", "value": 0}, {"label": "已转移对象", "value": 0}, {"label": "涉及人数合计", "value": 0}]

const rows = ref<EntryRow[]>([])
const total = ref(0)
const errorMessage = ref('')
const queryHint = ref('')
const typeOptions = ref<string[]>([])
const criteria = reactive<ThreatQuery>({
  对象编号: '',
  对象类型: [],
  最近距离下限: '',
  最近距离上限: '',
  涉及人数下限: '',
  涉及人数上限: '',
})
const statusSummary = computed(() =>
  statuses.map((status: string) => ({
    status,
    count: rows.value.filter((row) => String(row.status) === status).length,
  })),
)

function resetFilters() {
  criteria.对象编号 = ''
  criteria.对象类型 = []
  criteria.最近距离下限 = ''
  criteria.最近距离上限 = ''
  criteria.涉及人数下限 = ''
  criteria.涉及人数上限 = ''
  reload()
}

function exportRows() {
  downloadEntries(meta.key)
}

function openCreate() {
  errorMessage.value = '受威胁对象登记入口尚未接入审批流'
}

function runAction(action: string, row: EntryRow) {
  errorMessage.value = ''
  const result = applyAction(meta.key, Number(row.id), action)
  if (!result.ok) {
    errorMessage.value = result.message
    return
  }
  reload()
}

function reload() {
  errorMessage.value = ''
  queryHint.value = ''
  try {
    const payload = queryThreatEntries(criteria)
    if (payload.invalid) {
      // 条件里有无效值（越界、负数等）：本次查询退回，列表保持上一次的结果。
      errorMessage.value = payload.invalid
      return
    }
    rows.value = payload.items
    total.value = payload.total
    typeOptions.value = threatObjectTypes()
    if (payload.total === 0 && payload.blockers.length > 0) {
      queryHint.value = `没有符合条件的受威胁对象。${payload.blockers.join('；')}`
    }
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '受威胁对象列表读取失败'
  }
}

onMounted(reload)
</script>

<style scoped>
.range-inputs { display: flex; align-items: center; gap: 4px; }
.range-inputs input { width: 90px; }
.range-sep { color: var(--muted); }
.type-filter { flex-basis: 100%; }
.type-option { display: inline-flex; align-items: center; gap: 4px; margin-right: 12px; font-size: 13px; }
.query-hint { margin: 0 0 10px; font-size: 13px; color: #b42318; }
</style>
