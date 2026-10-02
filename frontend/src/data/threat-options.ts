/** 受威胁对象相关的共享口径：受威胁对象页登记、裂缝观测页核对项读同一套字典。 */

export const THREAT_TYPE_FIELD = '对象类型'

/** 现行对象类型：两个页面的下拉、多选都从这里取，保证读出来的对象类型一致。 */
export const THREAT_TYPES = [
  '居民点',
  '学校',
  '医院',
  '企事业单位',
  '道路交通',
  '基础设施',
  '农田',
  '其他',
] as const

/** 最近距离合理区间（米）：超出或填负数都按无效值退回。 */
export const DISTANCE_LIMIT = 10000

/** 涉及人数上限：超过上限按无效值退回。 */
export const POPULATION_LIMIT = 1000000

export const THREAT_STATUS = {
  pending: '待登记',
  registered: '已登记',
  transferred: '已转移',
  released: '已解除',
} as const
