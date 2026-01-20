use alloc::vec::Vec;

use p3_field::Field;
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
