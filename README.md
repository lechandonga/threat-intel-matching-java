# 威胁情报指标匹配服务（本地版）

纯本地运行的威胁情报指标服务：用本地数据模拟多个情报来源，不依赖任何外部服务或数据库。
支持 IP、域名、文件哈希（MD5/SHA-1/SHA-256）三类指标的**多来源导入、归一化合并、
撤回、幂等重导、判定查询、置信度时间衰减与白名单优先**。

技术栈：Java 21、Spring Boot 3.4、内存存储（数据保存在进程内）、JUnit 5。

## 快速开始

```bash
# 运行测试（日志按业务分组，展示每个业务的用例与通过情况）
mvn test

# 启动服务（默认加载 data/samples/ 下的两份示例来源，端口 8080）
mvn spring-boot:run

# 端口被占用时可换端口
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=18080
```

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/intel/import/{format}` | 导入一批情报，`format` 为 `stix` 或 `flat`，请求体为 JSON |
| GET | `/api/intel/query/{type}/{value}` | 判定查询，type 为 `ip`/`domain`/`md5`/`sha1`/`sha256` |
| GET | `/api/intel/query?type=&value=` | 同上，查询参数形式（推荐用于哈希） |
| GET | `/api/intel/whitelist` | 查看白名单 |
| POST | `/api/intel/whitelist` | 追加白名单，体为 `{"type":"ip","value":"8.8.8.8"}` |

导入响应：

```json
{ "accepted": 1, "unchanged": 0, "revoked": 0, "alreadyAbsent": 0,
  "rejected": [
    {"index": 0, "rawSnippet": "{...}", "reason": "MALFORMED_IP", "detail": "value=999.1.1.1"}
  ]}
```

判定响应（每条来源都给出原始结论、原始/衰减后置信度、评分、观测与入库时间、修订号，
`deciding=true` 为裁决中选来源）：

```json
{ "type":"IP","value":"203.0.113.10","verdict":"SUSPICIOUS",
  "whitelisted":false,"found":true,
  "decidingRule":"MAX_DECAYED_CONFIDENCE_THEN_WEIGHT_THEN_SOURCE_NAME",
  "decidingSource":"local-vendor-b","halfLifeDays":7.0,
  "sources":[{"source":"local-stix-a","disposition":"MALICIOUS","rawConfidence":90,
              "decayedConfidence":0.5506,"score":0.5506,"observedAt":"...",
              "firstSeen":"...","lastSeen":"...","revision":1,"deciding":false}]}
```

```bash
# 示例
curl -s -X POST localhost:8080/api/intel/import/stix \
  -H "Content-Type: application/json" --data @data/samples/stix-bundle.json
curl -s "localhost:8080/api/intel/query?type=ip&value=203.0.113.10"
```

## 支持的来源格式

### 1. STIX 2 Bundle（`format=stix`）

根对象为 bundle，指标放在 `objects` 数组中；非 `indicator` 对象忽略。

- 来源：`indicator.x_source` → `indicator.created_by_ref`（去掉 `identity--` 前缀）
  → bundle 的 `x_source` → bundle `id`（去掉 `bundle--` 前缀）。
- pattern 支持的子集：
  - `[ipv4-addr:value = '203.0.113.10']`
  - `[ipv6-addr:value = '2001:db8::1']`
  - `[domain-name:value = 'evil.example.com']`
  - `[file:hashes.'SHA-256' = '<hex>']`（同样支持 MD5 / SHA-1，带不带引号均可）
- 结论：取 `labels` 中的关键词（`malicious`/`malware`/`c2`/`ransomware` → 恶意；
  `suspicious`/`unknown` → 可疑；`benign`/`whitelist` → 良性），也可用 `x_disposition` 补充。
- 置信度：STIX 标准字段 `confidence`（0-100）。
- 时间：优先 `modified`，否则 `created`，ISO-8601。
- 撤回：`"revoked": true`。

### 2. 扁平厂商 Feed（`format=flat`）

```json
{
  "source": "local-vendor-b",
  "records": [
    {"indicator_type":"ip","value":"203.0.113.10","disposition":"suspicious",
     "confidence":95,"observed_at":"2026-10-05T12:00:00Z","revoked":false}
  ]
}
```

- `indicator_type`：`ip`/`ipv4`/`ipv6`、`domain`/`hostname`、`md5`/`sha1`/`sha256`、
  或 `hash`（此时按值长度推断算法：32/40/64 位十六进制）。
- `disposition`：`malicious`/`malware`/`bad`/`1`、`suspicious`/`suspect`/`2`、
  `benign`/`clean`/`harmless`/`0`。
- `confidence`：0-100 数字；`observed_at`：ISO-8601；`revoked`：可选布尔。
- 来源可写在文档级 `source`，也可由每条记录的 `source` 覆盖。

### 归一化规则

- IP：严格校验 IPv4/IPv6 格式并转成 JDK 规范化形式（拒绝主机名、越界段）。
- 域名：去尾部点、转小写、校验标签与长度（如 `WWW.Example.COM.` → `www.example.com`）。
- 哈希：转小写、必须纯十六进制，长度必须与声明算法一致。

### 坏数据处理

坏记录**逐条拒绝、绝不静默跳过，也不会导致整批失败**；好记录照常入库。
每条拒绝都带批次内下标 `index`、原始片段 `rawSnippet`、可区分的 `reason` 与 `detail`：
`MISSING_SOURCE`/`MISSING_TYPE`/`UNSUPPORTED_TYPE`/`MISSING_VALUE`/
`MALFORMED_IP`/`MALFORMED_DOMAIN`/`MALFORMED_HASH`/
`MISSING_DISPOSITION`/`UNSUPPORTED_DISPOSITION`/
`MISSING_CONFIDENCE`/`CONFIDENCE_NOT_NUMBER`/`CONFIDENCE_OUT_OF_RANGE`/
`MISSING_TIME`/`MALFORMED_TIME`/`UNSUPPORTED_PATTERN`/`STIX_OBJECT_NOT_INDICATOR`/
`DOCUMENT_NOT_OBJECT`/`MISSING_RECORDS`/`RECORDS_NOT_ARRAY`/`RECORD_NOT_OBJECT`。

## 合并与撤回规则

- 指标键 = 归一化后的 `(类型, 值)`。不同来源的同一指标合并为一条记录，
  内部按来源保留各自的观测（结论、原始置信度、观测时间、首次/最近入库时间、修订号）。
- 同一来源重复导入**完全相同**的记录时幂等：不计为更新、不增加修订号
  （响应中计入 `unchanged`）。内容发生实质变化时更新并 `revision + 1`。
- 撤回（STIX `revoked:true` 或 flat `"revoked":true`）只删除**该来源**的观测：
  其它来源仍有支撑时指标保留；最后一个来源撤回后指标才被移除。
  撤回本来就不存在的观测计入 `alreadyAbsent`，不报错，可重复撤回。
- 所有读写在同一把锁下原子完成，对外只暴露不可变快照；
  导入与查询并发时不会出现重复计数、更新丢失或读到中间状态。

## 判定、冲突裁决与置信度衰减

置信度按观测时间做指数衰减（半衰期可配，默认 7 天）：

```
decayedConfidence = (rawConfidence / 100) * 0.5 ^ (ageDays / halfLifeDays)
score             = dispositionWeight * decayedConfidence
```

结论权重固定：恶意 `1.0`、可疑 `0.5`、良性 `0.0`。

**与导入顺序无关的固定裁决规则：**

1. **白名单优先**：指标在白名单中时直接判 `HARMLESS`，响应仍保留全部命中来源作为证据，
   `decidingRule=WHITELIST_PRIORITY`。
2. 无任何情报时判 `HARMLESS`，`decidingRule=NO_INTEL`。
3. 否则按以下顺序选出唯一裁决来源（全序比较，必然确定）：
   1. 衰减后置信度最大者；
   2. 平分时结论权重更大者（恶意 > 可疑 > 良性）；
   3. 仍平分时来源标识字典序最前者。
4. 中选来源的 `score ≥ 0.75` → `MALICIOUS`；`score ≥ 0.25` → `SUSPICIOUS`；否则 `HARMLESS`。

白名单：默认从 `data/whitelist.txt` 加载（每行 `类型,值`，`#` 注释），
也可通过 POST 接口运行时追加。

配置项（`src/main/resources/application.properties`）：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `intel.confidence.half-life-days` | `7` | 置信度半衰期（天） |
| `intel.whitelist.file` | `data/whitelist.txt` | 本地白名单文件 |
| `intel.sample.load-on-startup` | `true` | 启动时是否加载示例情报 |

## 本地验证

```bash
mvn test
```

测试日志按业务分组打印（由 `BusinessLoggingListener` 输出 `==== 业务N ... ====` 横幅、
每个用例名与 PASS/FAIL、分组小结）：

| 测试类 | 覆盖业务 |
| --- | --- |
| `BadDataRejectionTest` | 字段缺失/格式非法/取值越界逐条拒绝、整批不失败、原因可区分 |
| `MergeWithdrawIdempotencyTest` | 多来源合并、归一化合并、幂等导入、修订号、撤回保留/移除、STIX 撤回 |
| `VerdictAdjudicationTest` | 冲突固定裁决、导入顺序互换结论一致、半衰期衰减、判定阈值、白名单优先、依据可追溯 |
| `ConcurrencyTest` | 16/24 线程并发导入、重复幂等、导入与查询并发无中间态、快照一致性 |
| `IntelApiWebTest` | REST 端到端：导入、查询、拒绝原因、白名单覆盖、400 错误 |

手工验证：

```bash
mvn spring-boot:run
curl -s localhost:8080/api/intel/query/ip/203.0.113.10
curl -s localhost:8080/api/intel/query/domain/phish.example.org
curl -s "localhost:8080/api/intel/query?type=sha256&value=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```
