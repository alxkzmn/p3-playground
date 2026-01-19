use alloc::{vec, vec::Vec};

use p3_field::{ExtensionField, Field, PackedFieldExtension, PackedValue};
use p3_util::log2_strict_usize;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::constraints::statement::EqStatement;

#[derive(Debug, Clone)]
pub enum LinearConstraint<F> {
    Dense(EvaluationsList<F>),
    TensorProduct {
        range_start: usize,
        log_range_len: usize,
        row_weights: EvaluationsList<F>,
        col_weights: EvaluationsList<F>,
    },
}

#[derive(Debug, Clone)]
pub struct LinearEqStatement<F> {
    base: EqStatement<F>,
    linear_weights: Vec<LinearConstraint<F>>,
    linear_evaluations: Vec<F>,
}

impl<F: Field> LinearEqStatement<F> {
    #[must_use]
    pub const fn initialize(num_variables: usize) -> Self {
        Self {
            base: EqStatement::initialize(num_variables),
            linear_weights: Vec::new(),
            linear_evaluations: Vec::new(),
        }
    }

    #[must_use]
    pub const fn num_variables(&self) -> usize {
        self.base.num_variables()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.base.len() + self.linear_weights.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.base.is_empty() && self.linear_weights.is_empty()
    }

    #[must_use]
    pub fn has_linear_constraints(&self) -> bool {
        !self.linear_weights.is_empty()
    }

    pub fn add_evaluated_constraint(
        &mut self,
        point: whir_p3::poly::multilinear::MultilinearPoint<F>,
        eval: F,
    ) {
        self.base.add_evaluated_constraint(point, eval);
    }

    pub fn add_linear_constraint(&mut self, weights: EvaluationsList<F>, eval: F) {
        assert_eq!(weights.num_variables(), self.num_variables());
        self.linear_weights.push(LinearConstraint::Dense(weights));
        self.linear_evaluations.push(eval);
    }

    pub fn add_tensor_product_constraint(
        &mut self,
        range_start: usize,
        log_range_len: usize,
        row_weights: EvaluationsList<F>,
        col_weights: EvaluationsList<F>,
        eval: F,
    ) {
        let range_len = 1usize << log_range_len;
        let row_len = col_weights.num_evals();
        let rows = row_weights.num_evals();
        assert_eq!(row_len * rows, range_len);
        assert_eq!(range_start % range_len, 0);
        self.linear_weights.push(LinearConstraint::TensorProduct {
            range_start,
            log_range_len,
            row_weights,
            col_weights,
        });
        self.linear_evaluations.push(eval);
    }

    pub fn combine_hypercube_with_linear<Base, const INITIALIZED: bool>(
        &self,
        acc_weights: &mut EvaluationsList<F>,
        acc_sum: &mut F,
        challenge: F,
    ) where
        Base: Field,
        F: ExtensionField<Base>,
    {
        if self.is_empty() {
            return;
        }

        let num_point_constraints = self.base.len();
        let num_linear_constraints = self.linear_weights.len();
        let num_constraints = num_point_constraints + num_linear_constraints;
        let challenges = challenge.powers().collect_n(num_constraints);

        if num_point_constraints > 0 {
            self.base
                .combine_hypercube::<Base, INITIALIZED>(acc_weights, acc_sum, challenge);
        }

        if num_linear_constraints > 0 {
            let mut out = acc_weights.as_slice().to_vec();
            let mut start = 0;
            if !INITIALIZED && num_point_constraints == 0 {
                let alpha = challenges[num_point_constraints];
                match &self.linear_weights[0] {
                    LinearConstraint::Dense(weights) => {
                        out.iter_mut()
                            .zip(weights.iter().copied())
                            .for_each(|(out, w)| *out = alpha * w);
                    }
                    LinearConstraint::TensorProduct {
                        range_start,
                        log_range_len,
                        row_weights,
                        col_weights,
                    } => {
                        let range_len = 1usize << log_range_len;
                        let row_len = col_weights.num_evals();
                        let out_slice = &mut out[*range_start..*range_start + range_len];
                        out_slice
                            .chunks_mut(row_len)
                            .zip(row_weights.as_slice().iter().copied())
                            .for_each(|(row_out, row_w)| {
                                let scale = alpha * row_w;
                                row_out
                                    .iter_mut()
                                    .zip(col_weights.as_slice().iter().copied())
                                    .for_each(|(out, w)| *out = scale * w);
                            });
                    }
                }
                *acc_sum += alpha * self.linear_evaluations[0];
                start = 1;
            }

            for j in start..num_linear_constraints {
                let alpha = challenges[num_point_constraints + j];
                match &self.linear_weights[j] {
                    LinearConstraint::Dense(weights) => {
                        out.iter_mut()
                            .zip(weights.iter().copied())
                            .for_each(|(out, w)| *out += alpha * w);
                    }
                    LinearConstraint::TensorProduct {
                        range_start,
                        log_range_len,
                        row_weights,
                        col_weights,
                    } => {
                        let range_len = 1usize << log_range_len;
                        let row_len = col_weights.num_evals();
                        let out_slice = &mut out[*range_start..*range_start + range_len];
                        out_slice
                            .chunks_mut(row_len)
                            .zip(row_weights.as_slice().iter().copied())
                            .for_each(|(row_out, row_w)| {
                                let scale = alpha * row_w;
                                row_out
                                    .iter_mut()
                                    .zip(col_weights.as_slice().iter().copied())
                                    .for_each(|(out, w)| *out += scale * w);
                            });
                    }
                }
                *acc_sum += alpha * self.linear_evaluations[j];
            }

            *acc_weights = EvaluationsList::new(out);
        }
    }

    pub fn combine_hypercube_packed_with_linear<Base, const INITIALIZED: bool>(
        &self,
        weights: &mut EvaluationsList<F::ExtensionPacking>,
        sum: &mut F,
        challenge: F,
    ) where
        Base: Field,
        F: ExtensionField<Base>,
    {
        if self.is_empty() {
            return;
        }

        let num_point_constraints = self.base.len();
        let num_linear_constraints = self.linear_weights.len();
        let num_constraints = num_point_constraints + num_linear_constraints;
        let challenges = challenge.powers().collect_n(num_constraints);

        if num_point_constraints > 0 {
            self.base
                .combine_hypercube_packed::<Base, INITIALIZED>(weights, sum, challenge);
        }

        if num_linear_constraints == 0 {
            return;
        }

        let k = self.num_variables();
        let k_pack = log2_strict_usize(Base::Packing::WIDTH);
        assert!(k >= k_pack);
        assert_eq!(weights.num_variables() + k_pack, k);

        let mut out = weights.as_slice().to_vec();
        let mut start = 0;
        if !INITIALIZED && num_point_constraints == 0 {
            let alpha = challenges[num_point_constraints];
            let alpha_packed = F::ExtensionPacking::from(alpha);
            match &self.linear_weights[0] {
                LinearConstraint::Dense(w) => {
                    out.iter_mut()
                        .zip(w.as_slice().chunks(Base::Packing::WIDTH))
                        .for_each(|(out, chunk)| {
                            let packed = F::ExtensionPacking::from_ext_slice(chunk);
                            *out = alpha_packed * packed;
                        });
                }
                LinearConstraint::TensorProduct {
                    range_start,
                    log_range_len,
                    row_weights,
                    col_weights,
                } => {
                    let range_len = 1usize << log_range_len;
                    let row_len = col_weights.num_evals();
                    let range_end = *range_start + range_len;
                    let pack_width = Base::Packing::WIDTH;
                    let start_pack = range_start / pack_width;
                    let end_pack = (range_end - 1) / pack_width;
                    let log_row_len = log2_strict_usize(row_len);
                    let mut scratch = vec![F::ZERO; pack_width];
                    for pack_idx in start_pack..=end_pack {
                        let base = pack_idx * pack_width;
                        for i in 0..pack_width {
                            let idx = base + i;
                            if idx >= *range_start && idx < range_end {
                                let local = idx - range_start;
                                let row = local >> log_row_len;
                                let col = local & (row_len - 1);
                                scratch[i] =
                                    row_weights.as_slice()[row] * col_weights.as_slice()[col];
                            } else {
                                scratch[i] = F::ZERO;
                            }
                        }
                        let packed = F::ExtensionPacking::from_ext_slice(&scratch);
                        out[pack_idx] = alpha_packed * packed;
                    }
                }
            }
            start = 1;
        }

        if k_pack * 2 > k {
            for j in start..num_linear_constraints {
                let alpha = challenges[num_point_constraints + j];
                let alpha_packed = F::ExtensionPacking::from(alpha);
                match &self.linear_weights[j] {
                    LinearConstraint::Dense(w) => {
                        out.iter_mut()
                            .zip(w.as_slice().chunks(Base::Packing::WIDTH))
                            .for_each(|(out, chunk)| {
                                let packed = F::ExtensionPacking::from_ext_slice(chunk);
                                *out += alpha_packed * packed;
                            });
                    }
                    LinearConstraint::TensorProduct {
                        range_start,
                        log_range_len,
                        row_weights,
                        col_weights,
                    } => {
                        let range_len = 1usize << log_range_len;
                        let row_len = col_weights.num_evals();
                        let range_end = *range_start + range_len;
                        let pack_width = Base::Packing::WIDTH;
                        let start_pack = range_start / pack_width;
                        let end_pack = (range_end - 1) / pack_width;
                        let log_row_len = log2_strict_usize(row_len);
                        let mut scratch = vec![F::ZERO; pack_width];
                        for pack_idx in start_pack..=end_pack {
                            let base = pack_idx * pack_width;
                            for i in 0..pack_width {
                                let idx = base + i;
                                if idx >= *range_start && idx < range_end {
                                    let local = idx - range_start;
                                    let row = local >> log_row_len;
                                    let col = local & (row_len - 1);
                                    scratch[i] =
                                        row_weights.as_slice()[row] * col_weights.as_slice()[col];
                                } else {
                                    scratch[i] = F::ZERO;
                                }
                            }
                            let packed = F::ExtensionPacking::from_ext_slice(&scratch);
                            out[pack_idx] += alpha_packed * packed;
                        }
                    }
                }
            }
            *weights = EvaluationsList::new(out);
            return;
        }

        for j in start..num_linear_constraints {
            let alpha = challenges[num_point_constraints + j];
            let alpha_packed = F::ExtensionPacking::from(alpha);
            match &self.linear_weights[j] {
                LinearConstraint::Dense(w) => {
                    out.iter_mut()
                        .zip(w.as_slice().chunks(Base::Packing::WIDTH))
                        .for_each(|(out, chunk)| {
                            let packed = F::ExtensionPacking::from_ext_slice(chunk);
                            *out += alpha_packed * packed;
                        });
                }
                LinearConstraint::TensorProduct {
                    range_start,
                    log_range_len,
                    row_weights,
                    col_weights,
                } => {
                    let range_len = 1usize << log_range_len;
                    let row_len = col_weights.num_evals();
                    let range_end = *range_start + range_len;
                    let pack_width = Base::Packing::WIDTH;
                    let start_pack = range_start / pack_width;
                    let end_pack = (range_end - 1) / pack_width;
                    let log_row_len = log2_strict_usize(row_len);
                    let mut scratch = vec![F::ZERO; pack_width];
                    for pack_idx in start_pack..=end_pack {
                        let base = pack_idx * pack_width;
                        for i in 0..pack_width {
                            let idx = base + i;
                            if idx >= *range_start && idx < range_end {
                                let local = idx - range_start;
                                let row = local >> log_row_len;
                                let col = local & (row_len - 1);
                                scratch[i] =
                                    row_weights.as_slice()[row] * col_weights.as_slice()[col];
                            } else {
                                scratch[i] = F::ZERO;
                            }
                        }
                        let packed = F::ExtensionPacking::from_ext_slice(&scratch);
                        out[pack_idx] += alpha_packed * packed;
                    }
                }
            }
        }
        *weights = EvaluationsList::new(out);
    }

    pub fn combine_evals_with_linear(&self, claimed_eval: &mut F, gamma: F) {
        let num_point_constraints = self.base.len();
        if num_point_constraints > 0 {
            self.base.combine_evals(claimed_eval, gamma);
        }
        if !self.linear_evaluations.is_empty() {
            let total = self.len();
            let start = num_point_constraints;
            *claimed_eval += p3_field::dot_product::<F, _, _>(
                self.linear_evaluations.iter().copied(),
                gamma.powers().skip(start).take(total - start),
            );
        }
    }

    pub fn into_eq_statement(self) -> EqStatement<F> {
        let mut base = self.base;
        for (weights, eval) in self
            .linear_weights
            .into_iter()
            .zip(self.linear_evaluations.into_iter())
        {
            match weights {
                LinearConstraint::Dense(weights) => base.add_linear_constraint(weights, eval),
                LinearConstraint::TensorProduct {
                    range_start,
                    log_range_len,
                    row_weights,
                    col_weights,
                } => base.add_tensor_product_constraint(
                    range_start,
                    log_range_len,
                    row_weights,
                    col_weights,
                    eval,
                ),
            }
        }
        base
    }
}

impl<F: Field> From<EqStatement<F>> for LinearEqStatement<F> {
    fn from(base: EqStatement<F>) -> Self {
        Self {
            base,
            linear_weights: Vec::new(),
            linear_evaluations: Vec::new(),
        }
    }
}
