/** 纯前端数据层的公共类型：与全栈版后端返回的结构保持一致，换回后端时页面不用改。 */

export type EntryRow = {
  id: number
  status: string
  pending: boolean
  abnormal: boolean
  [field: string]: string | number | boolean
}

export type ModuleMeta = {
  key: string
  name: string
  entity: string
  desc: string
  fields: string[]
  statuses: string[]
  actions: string[]
  actionTargets: Record<string, string>
  metrics: string[]
  /** 为 true 时状态只能按 statuses 的顺序逐环流转，跳环节会被挡回。 */
  strictOrder?: boolean
}

export type PageResult = {
  items: EntryRow[]
  total: number
  page: number
  size: number
}

export type ActionResult = {
  ok: boolean
  message: string
}

/** 受威胁对象的条件定位入参：编号模糊、类型多选、距离与人数按区间卡。 */
export type ThreatQuery = {
  对象编号: string
  对象类型: string[]
  最近距离下限: string
  最近距离上限: string
  涉及人数下限: string
  涉及人数上限: string
}

export type ThreatQueryResult = PageResult & {
  /** 非空表示查询条件里有无效值（越界、负数等），本次查询被退回。 */
  invalid: string
  /** 查不到记录时，说明卡在哪一项条件上。 */
  blockers: string[]
}

export type OverviewResult = {
  cards: { label: string; value: number }[]
  modules: { name: string; created: number; pending: number; abnormal: number }[]
}
