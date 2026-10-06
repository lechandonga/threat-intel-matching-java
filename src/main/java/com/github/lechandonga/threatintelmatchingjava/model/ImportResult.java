package com.github.lechandonga.threatintelmatchingjava.model;

import java.util.List;

/**
 * 一次批次导入的结果。
 *
 * @param accepted      本次新写入或实质更新的记录数
 * @param unchanged     与存量完全一致、幂等跳过的记录数
 * @param revoked       本次撤回生效的（来源, 指标）数
 * @param alreadyAbsent 撤回目标本来就不存在的条数
 * @param rejected      被拒绝的坏记录（含可区分原因）
 */
public record ImportResult(
        int accepted,
        int unchanged,
        int revoked,
        int alreadyAbsent,
        List<RejectedRecord> rejected
) {
    public int totalInBatch() {
        return accepted + unchanged + revoked + alreadyAbsent + rejected.size();
    }
}
