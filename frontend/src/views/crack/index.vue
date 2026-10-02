<template>
  <section class="page" data-module="crack">
    <header class="page-head">
      <div>
        <h2>裂缝观测管理</h2>
        <p class="page-desc">维护裂缝观测记录，围绕裂缝编号、所属隐患点、裂缝走向、本期宽度做登记、筛选与状态流转；受威胁对象确认转移后会同步出一条转移核对项。</p>
      </div>
      <div class="page-actions">
        <button class="btn primary" type="button" @click="openCreate">登记裂缝观测记录</button>
        <button class="btn" type="button" @click="exportRows">导出裂缝观测清单</button>
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
      <span class="legend-item">转移核对项：{{ transferCheckCount }}</span>
    </p>

    <form class="filter-bar" @submit.prevent="reload">
      <label v-for="field in filterFields" :key="field" class="filter-item">
        <span>{{ field }}</span>
        <input v-model="filters[field]" :placeholder="`按${field}检索`" />
      </label>
      <label class="filter-item check-pill">
        <input v-model="onlyTransferCheck" type="checkbox" @change="reload" />
        只看转移核对项
      </label>
      <button class="btn" type="submit">查询</button>
      <button class="btn ghost" type="button" @click="resetFilters">重置条件</button>
    </form>

    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in columns" :key="column">{{ column }}</th>
          <th>当前状态</th>
          <th>可执行动作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)" :class="{ 'check-row': isTransferCheck(row) }">
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
          <td :colspan="columns.length + 2" class="empty-state">暂无裂缝观测数据，可先登记裂缝观测记录</td>
        </tr>
      </tbody>
    </table>

    <footer class="page-foot">
      <span>共 {{ total }} 条裂缝观测记录</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import {
  downloadEntries,
  listEntries,
  moduleMeta,
  runAction as applyAction,
} from '@/api/local-service'
import { THREAT_TYPE_FIELD } from '@/data/threat-options'
import type { EntryRow } from '@/data/types'

const meta = moduleMeta('crack')
// 对象类型列读的就是受威胁对象同步过来的原值，两处一份字典、一个口径。
const columns = ["裂缝编号", "所属隐患点", THREAT_TYPE_FIELD, "裂缝走向", "本期宽度", "累计变宽", "观测日期", "观测人", "裂缝状态"]
const actions = ["提交观测", "标记变宽", "登记封填"]
const statuses = ["待观测", "稳定", "持续变宽", "已封填"]

const rows = ref<EntryRow[]>([])
const allCache = ref<EntryRow[]>([])
const total = ref(0)
const errorMessage = ref('')
const filters = ref<Record<string, string>>({})
const onlyTransferCheck = ref(false)
const filterFields = ["裂缝编号", "所属隐患点", THREAT_TYPE_FIELD]
const statusSummary = computed(() =>
  statuses.map((status: string) => ({
    status,
    count: allCache.value.filter((row) => String(row.status) === status).length,
  })),
)
const transferCheckCount = computed(() => allCache.value.filter(isTransferCheck).length)
const stats = computed(() => [
  { label: '待观测裂缝', value: allCache.value.filter((row) => String(row.status) === '待观测').length },
  { label: '持续变宽裂缝', value: allCache.value.filter((row) => String(row.status) === '持续变宽').length },
  { label: '转移核对项', value: transferCheckCount.value },
])

function isTransferCheck(row: EntryRow): boolean {
  return String(row['裂缝编号'] ?? '').startsWith('XFER-')
}

function resetFilters() {
  filters.value = {}
  onlyTransferCheck.value = false
  reload()
}

function exportRows() {
  downloadEntries(meta.key)
}

function openCreate() {
  errorMessage.value = '裂缝观测记录登记入口尚未接入审批流'
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
  try {
    allCache.value = listEntries(meta.key).items
    let payload = listEntries(meta.key, filters.value)
    if (onlyTransferCheck.value) {
      payload = { ...payload, items: payload.items.filter(isTransferCheck), total: payload.items.filter(isTransferCheck).length }
    }
    rows.value = payload.items
    total.value = payload.total
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '裂缝观测列表读取失败'
  }
}

onMounted(reload)
</script>
