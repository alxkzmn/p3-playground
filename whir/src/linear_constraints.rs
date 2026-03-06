use alloc::vec::Vec;

use p3_field::Field;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::constraints::statement::EqStatement;
use whir_p3::whir::constraints::statement::eq::LinearConstraint;

#[derive(Debug, Clone)]
pub struct LinearEqStatement<F> {
    base: EqStatement<F>,
    linear_constraints: Vec<LinearConstraint<F>>,
    linear_evaluations: Vec<F>,
}

impl<F: Field> LinearEqStatement<F> {
    #[must_use]
    pub const fn initialize(num_variables: usize) -> Self {
        Self {
            base: EqStatement::initialize(num_variables),
            linear_constraints: Vec::new(),
            linear_evaluations: Vec::new(),
        }
    }

    #[must_use]
    pub const fn num_variables(&self) -> usize {
        self.base.num_variables()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.base.len() + self.linear_constraints.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.base.is_empty() && self.linear_constraints.is_empty()
    }

    #[must_use]
    pub fn has_linear_constraints(&self) -> bool {
        !self.linear_constraints.is_empty()
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
        self.linear_constraints
            .push(LinearConstraint::Dense(weights));
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
        self.linear_constraints
            .push(LinearConstraint::TensorProduct {
                range_start,
                log_range_len,
                row_weights,
                col_weights,
            });
        self.linear_evaluations.push(eval);
    }

    pub fn into_eq_statement(self) -> EqStatement<F> {
        let mut base = self.base;
        for (weights, eval) in self
            .linear_constraints
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
