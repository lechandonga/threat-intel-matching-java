package com.github.lechandonga.threatintelmatchingjava.model;

import java.util.List;

/** Outcome of a batch import. Bad rows never abort the good rows in the same batch. */
public record ImportResult(
        String sourceId,
        int received,
        int accepted,
        int rejected,
        int merged,
        int unchanged,
        List<ImportRejection> rejections) {
}
