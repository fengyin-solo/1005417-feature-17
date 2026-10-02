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
  /** 开启后动作只能沿 statuses 逐格向前，跳格、回退都会被挡回。 */
  strictFlow?: boolean
}

export type PageResult = {
  items: EntryRow[]
  total: number
  page: number
  size: number
  /** 查询为空时逐项给出的卡点说明（哪一项条件把结果卡死了）。 */
  blocked?: BlockedCondition[]
}

export type ActionResult = {
  ok: boolean
  message: string
  /** 命中连续提交去重，本次没有重复落数据。 */
  duplicated?: boolean
}

export type FieldError = {
  field: string
  message: string
}

export type SaveResult = ActionResult & {
  errors?: FieldError[]
}

export type OverviewResult = {
  cards: { label: string; value: number }[]
  modules: { name: string; created: number; pending: number; abnormal: number }[]
}

/** 区间条件：最近距离 / 涉及人数这类数值字段按上下限卡。 */
export type RangeFilter = {
  kind?: 'distance' | 'count'
  min?: string
  max?: string
}

/** 单个字段的条件形态：文本包含、多选其一、数值区间。 */
export type FieldFilter = string | string[] | RangeFilter

export type ListFilters = Record<string, FieldFilter>

export type BlockedCondition = {
  field: string
  message: string
}

/** 受威胁对象登记草稿：表单全部按文本收集，由服务层校验后再转类型。 */
export type ThreatDraft = {
  对象编号: string
  所属隐患点: string
  对象类型: string
  对象名称: string
  涉及人数: string
  最近距离: string
  联系人: string
}
