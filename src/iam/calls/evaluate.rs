use crate::iam::{
    policy::Evaluate,
    types::{Effect, Statement},
};

impl Evaluate {
    /// Recopila todas las declaraciones (`Statement`) de las políticas, grupos y roles
    /// dentro de `Evaluate`. Esta función es fundamental para obtener un conjunto consolidado
    /// de declaraciones para su posterior análisis.
    fn gather_statements(&self) -> Vec<Statement> {
        let mut statements = Vec::new();
        for policy in &self.policies {
            statements.extend_from_slice(&policy.statements);
        }
        for group in &self.groups {
            for policy in &group.policies {
                statements.extend_from_slice(&policy.statements);
            }
        }
        for role in &self.roles {
            for policy in &role.policies {
                statements.extend_from_slice(&policy.statements);
            }
        }
        statements
    }

    /// Devuelve todas las declaraciones de tipo 'Allow' de las políticas asociadas.
    /// Filtra las declaraciones recopiladas para obtener solo aquellas con un efecto 'Allow'.
    /// Extrae y devuelve los recursos asociados con estas declaraciones.
    pub fn get_all_allow_statements(&self) -> Vec<String> {
        self.gather_statements()
            .into_iter()
            .filter(|statement| statement.effect == Effect::Allow)
            .map(|statement| statement.resource)
            .flatten()
            .collect()
    }

    /// Devuelve todas las declaraciones de tipo 'Deny' de las políticas asociadas.
    /// Funciona de manera similar a `get_all_allow_statements`, pero para declaraciones con efecto 'Deny'.
    /// Extrae y devuelve los recursos asociados con estas declaraciones.
    pub fn get_all_deny_statements(&self) -> Vec<String> {
        self.gather_statements()
            .into_iter()
            .filter(|statement| statement.effect == Effect::Deny)
            .map(|statement| statement.resource)
            .flatten()
            .collect()
    }

    /// Obtiene todas las acciones de las declaraciones de tipo 'Allow'.
    /// Esta función filtra y recopila las acciones de las declaraciones con efecto 'Allow'.
    pub fn get_all_allow_statements_action(&self) -> Vec<String> {
        self.gather_statements()
            .into_iter()
            .filter(|statement| statement.effect == Effect::Allow)
            .map(|statement| statement.action)
            .flatten()
            .collect()
    }

    /// Obtiene todas las acciones de las declaraciones de tipo 'Deny'.
    /// Similar a `get_all_allow_statements_action`, pero para declaraciones con efecto 'Deny'.
    pub fn get_all_deny_statements_action(&self) -> Vec<String> {
        self.gather_statements()
            .into_iter()
            .filter(|statement| statement.effect == Effect::Deny)
            .map(|statement| statement.action)
            .flatten()
            .collect()
    }
}
