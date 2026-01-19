use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, PackedFieldExtension, PackedValue};
use p3_util::log2_strict_usize;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::constraints::statement::EqStatement;

#[derive(Debug, Clone)]
pub struct LinearEqStatement<F> {
    base: EqStatement<F>,
    linear_weights: Vec<EvaluationsList<F>>,
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
        self.linear_weights.push(weights);
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
            self.linear_weights
                .iter()
                .zip(self.linear_evaluations.iter())
                .enumerate()
                .for_each(|(j, (weights, &expected))| {
                    let alpha = challenges[num_point_constraints + j];
                    let mut out = acc_weights.as_slice().to_vec();
                    if INITIALIZED || num_point_constraints > 0 || j > 0 {
                        out.iter_mut()
                            .zip(weights.iter().copied())
                            .for_each(|(out, w)| *out += alpha * w);
                    } else {
                        out.iter_mut()
                            .zip(weights.iter().copied())
                            .for_each(|(out, w)| *out = alpha * w);
                    }
                    *acc_weights = EvaluationsList::new(out);
                    *acc_sum += alpha * expected;
                });
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

        if k_pack * 2 > k {
            self.linear_weights
                .iter()
                .zip(self.linear_evaluations.iter())
                .enumerate()
                .for_each(|(j, (w, _expected))| {
                    let alpha = challenges[num_point_constraints + j];
                    let alpha_packed = F::ExtensionPacking::from(alpha);
                    let mut out = weights.as_slice().to_vec();
                    out.iter_mut()
                        .zip(w.as_slice().chunks(Base::Packing::WIDTH))
                        .for_each(|(out, chunk)| {
                            let packed = F::ExtensionPacking::from_ext_slice(chunk);
                            if INITIALIZED || num_point_constraints > 0 || j > 0 {
                                *out += alpha_packed * packed;
                            } else {
                                *out = alpha_packed * packed;
                            }
                        });
                    *weights = EvaluationsList::new(out);
                });
            return;
        }

        self.linear_weights.iter().enumerate().for_each(|(j, w)| {
            let alpha = challenges[num_point_constraints + j];
            let alpha_packed = F::ExtensionPacking::from(alpha);
            let mut out = weights.as_slice().to_vec();
            out.iter_mut()
                .zip(w.as_slice().chunks(Base::Packing::WIDTH))
                .for_each(|(out, chunk)| {
                    let packed = F::ExtensionPacking::from_ext_slice(chunk);
                    if INITIALIZED || num_point_constraints > 0 || j > 0 {
                        *out += alpha_packed * packed;
                    } else {
                        *out = alpha_packed * packed;
                    }
                });
            *weights = EvaluationsList::new(out);
        });
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
            base.add_linear_constraint(weights, eval);
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
