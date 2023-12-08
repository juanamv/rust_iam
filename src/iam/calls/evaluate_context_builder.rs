use globset::{GlobBuilder, GlobSetBuilder};

use crate::iam::{
    policy::{Evaluate, EvaluateContextBuilder},
    types::{Condition, Effect, Operator, Statement},
};

/// `EvaluateContextBuilder` es una clase que facilita la construcción y evaluación de un contexto de evaluación (`EvaluateContext`).
/// Proporciona métodos para evaluar políticas, roles y grupos, y determinar si se permiten o deniegan acciones y recursos específicos.
impl EvaluateContextBuilder {
    /// Recopila todas las declaraciones (`Statement`) de las políticas, grupos y roles
    /// asociados con el contexto actual.
    ///
    /// Devuelve un vector de `Statement`.
    pub fn gather_statements(&self) -> Vec<Statement> {
        let mut statements = Vec::new();
        for policy in &self.context.policies {
            statements.extend_from_slice(&policy.statements);
        }
        for group in &self.context.groups {
            for policy in &group.policies {
                statements.extend_from_slice(&policy.statements);
            }
        }
        for role in &self.context.roles {
            for policy in &role.policies {
                statements.extend_from_slice(&policy.statements);
            }
        }
        statements
    }

    /// Evalúa los permisos para un conjunto dado de declaraciones.
    ///
    /// # Argumentos
    /// * `statements` - Un vector de referencias a `Statement`.
    ///
    /// # Devuelve
    /// Una tupla `(bool, String)` donde el `bool` indica si se permite o no la acción,
    /// y el `String` proporciona un mensaje descriptivo.
    fn evaluate_permission_for_statements(&self, statements: &Vec<Statement>) -> (bool, String) {
        let mut allowed: (bool, String) = (
            false,
            "[Policy] User doesn't have required attributes".to_string(),
        );

        let (deny_statements, allow_statements): (Vec<_>, Vec<_>) =
            statements.iter().partition(|&s| s.effect == Effect::Deny);

        for _ in deny_statements {
            let deny_message =
                "[Deny] Policy has complete required attributes and is denied".to_string();

            let match_pattern = EvaluateContextBuilder::check_match(
                "resource",
                &self.all_deny_statements_resource,
                &self.context.resource,
            );

            let match_action = EvaluateContextBuilder::check_match(
                "action",
                &self.all_deny_statements_action,
                &self.context.action,
            );

            if match_pattern.0 && match_action.0 {
                return (false, deny_message);
            } else {
                if !match_pattern.0 {
                    allowed = match_pattern;
                } else {
                    allowed = match_action;
                }
            }
        }

        if allowed.0 {
            return (false, allowed.1);
        }

        for statement in allow_statements {
            let a = self.matches_conditions(&statement.condition, false);
            if a.0 {
                let match_pattern = EvaluateContextBuilder::check_match(
                    "resource",
                    &self.all_allow_statements_resource,
                    &self.context.resource,
                );

                let match_action = EvaluateContextBuilder::check_match(
                    "action",
                    &self.all_allow_statements_action,
                    &self.context.action,
                );

                if match_pattern.0 && match_action.0 {
                    allowed = (true, a.1);
                    break;
                } else {
                    if !match_pattern.0 {
                        allowed = match_pattern;
                    } else {
                        allowed = match_action;
                    }
                }
            } else {
                allowed = a;
            }
        }

        return allowed;
    }

    /// Evalúa las políticas dentro del contexto actual para determinar los permisos.
    ///
    /// # Devuelve
    /// Una tupla `(bool, String)` indicando el resultado de la evaluación y un mensaje descriptivo.
    pub fn evaluate_policy(&self) -> (bool, String) {
        let statements = self.gather_statements();

        if statements.is_empty() {
            return (false, "[Policy] User doesn't have any policies".to_string());
        }

        let allowed = self.evaluate_permission_for_statements(&statements);

        return allowed;
    }

    /// Determina si se puede asumir un rol basado en las políticas de confianza del contexto.
    ///
    /// # Devuelve
    /// Una tupla `(bool, String)` indicando si el rol puede ser asumido y un mensaje descriptivo.
    fn can_assume_role(&self) -> (bool, String) {
        let trust_policies = self
            .context
            .roles
            .iter()
            .flat_map(|r| &r.trust_policy)
            .collect::<Vec<_>>();

        if trust_policies.is_empty() {
            return (
                false,
                "[Trust policy] Role doesn't have trust policy".to_string(),
            );
        }

        let mut resp = (
            false,
            "[Trust policy] User doesn't have required attributes".to_string(),
        );

        for trust_policy in trust_policies {
            for statement in &trust_policy.statements {
                let match_condition = self.matches_conditions(&statement.condition, false);
                if !(statement.effect == Effect::Allow && match_condition.0) {
                    return (false, format!("[Trust policy] {}", match_condition.1));
                }
                resp = (match_condition.0, match_condition.1);
            }
        }
        resp
    }

    /// Evalúa si las condiciones dadas se cumplen dentro del contexto actual.
    ///
    /// # Argumentos
    /// * `conditions` - Un vector de `Condition`.
    /// * `deny` - Un booleano que indica si se evalúa una condición de denegación.
    ///
    /// # Devuelve
    /// Una tupla `(bool, String)` indicando si las condiciones se cumplen y un mensaje descriptivo.
    fn matches_conditions(&self, conditions: &Vec<Condition>, deny: bool) -> (bool, String) {
        for condition in conditions {
            match condition.operator {
                Operator::Eq => {
                    if !self
                        .context
                        .context
                        .get(&condition.key)
                        .map_or(false, |v| v.contains(&condition.value))
                    {
                        return (
                            false,
                            format!(
                                "[Condition] User doesn't have required attribute {} equals {}",
                                condition.key, condition.value
                            ),
                        );
                    }
                }
                _ => {
                    return (false, "[Condition] Unsupported operator".to_string());
                }
            }
        }

        let message = if deny {
            "[Deny] Policy has complete required attributes and is denied".to_string()
        } else {
            "[Allow] Policy has complete required attributes".to_string()
        };

        (true, message)
    }

    /// Evalúa las políticas asociadas con los roles en el contexto actual.
    ///
    /// # Devuelve
    /// Una tupla `(bool, String)` indicando si se permiten las políticas de los roles y un mensaje descriptivo.
    /// Si ningún rol tiene políticas, devuelve un mensaje indicando que no hay políticas.
    pub fn evaluate_role_policies(&self) -> (bool, String) {
        let rol_policies = self
            .context
            .roles
            .iter()
            .flat_map(|r| &r.policies)
            .collect::<Vec<_>>();

        for _ in rol_policies {
            return self.evaluate_policy();
        }
        (false, "[Role] Role doesn't have any policies".to_string())
    }

    /// Evalúa las políticas asociadas con el usuario, incluyendo políticas directas, políticas de grupo y políticas de rol.
    ///
    /// # Devuelve
    /// Una tupla `(bool, String)` que indica si se permiten o no las acciones y recursos basados en las políticas del usuario,
    /// y proporciona un mensaje descriptivo.
    /// Si el usuario no tiene grupos, roles ni políticas asociados, devuelve un mensaje indicativo.
    pub fn evaluate_user_policies(&self) -> (bool, String) {
        let mut allowed: (bool, String) = (false, "".to_string());

        if &self.context.groups.len() < &1
            && &self.context.roles.len() < &1
            && &self.context.policies.len() < &1
        {
            return (
                false,
                format!("[Groups, Roles, Policies] User doesn't have any groups, roles, policies"),
            );
        }

        for policy in &self.context.policies {
            for _ in &policy.statements {
                let result = self.evaluate_policy();
                if result.0 {
                    return result;
                }
                allowed = (result.0, result.1);
            }
        }

        for group in &self.context.groups {
            for _ in &group.policies {
                let result = self.evaluate_policy();
                if result.0 {
                    return result;
                }
                allowed = (result.0, result.1);
            }
        }

        for _ in &self.context.roles {
            let result = self.assume_role();
            if result.0 {
                return result;
            } else {
                allowed = (result.0, result.1)
            }
        }

        return allowed;
    }

    /// Inicializa un `EvaluateContextBuilder` con el contexto dado.
    ///
    /// # Argumentos
    /// * `context` - Referencia a un `Evaluate`, el contexto de evaluación.
    ///
    /// # Devuelve
    /// Una instancia de `EvaluateContextBuilder` inicializada con el contexto y los estados de permisos precalculados.
    pub fn init_context(context: &Evaluate) -> EvaluateContextBuilder {
        EvaluateContextBuilder {
            context: context.clone(),
            all_deny_statements_resource: context.get_all_deny_statements(),
            all_allow_statements_resource: context.get_all_allow_statements(),
            all_allow_statements_action: context.get_all_allow_statements_action(),
            all_deny_statements_action: context.get_all_deny_statements_action(),
        }
    }

    /// Evalúa si el contexto actual puede asumir un rol y, de ser así, evalúa las políticas asociadas con ese rol.
    ///
    /// # Devuelve
    /// Una tupla `(bool, String)` indicando si el rol puede ser asumido y, en caso afirmativo, el resultado de la evaluación de sus políticas.
    fn assume_role(&self) -> (bool, String) {
        let can_asume_role: (bool, String) = self.can_assume_role();

        if can_asume_role.0 {
            self.evaluate_role_policies()
        } else {
            can_asume_role
        }
    }

    /// Comprueba si las entidades en el contexto dado coinciden con los patrones especificados.
    ///
    /// # Argumentos
    /// * `entity_type` - Una cadena de texto que describe el tipo de entidad (por ejemplo, 'recurso' o 'acción').
    /// * `pattern_policy` - Un slice de `String` que contiene patrones contra los cuales se compararán las entidades.
    /// * `path_context` - Un slice de `String` que contiene las entidades a comparar.
    ///
    /// # Devuelve
    /// Una tupla `(bool, String)` que indica si hay una coincidencia y un mensaje descriptivo.
    /// En caso de errores al procesar patrones, devuelve un mensaje de error.
    pub fn check_match(
        entity_type: &str,
        pattern_policy: &[String],
        path_context: &[String],
    ) -> (bool, String) {
        let mut builder = GlobSetBuilder::new();
        for pattern in pattern_policy {
            match GlobBuilder::new(pattern).build() {
                Ok(g) => builder.add(g),
                Err(_) => {
                    return (
                        false,
                        format!("[Match] Error processing pattern '{}'", pattern),
                    )
                }
            };
        }
        let globset = match builder.build() {
            Ok(g) => g,
            Err(_) => return (false, "[Match] Error building globset".to_string()),
        };

        let mut matches = vec![];
        for entity in path_context {
            if globset.is_match(entity) {
                matches.push(entity);
            }
        }

        if !matches.is_empty() {
            (
                true,
                format!(
                    "[Match] The {} '{:?}' matches one of the patterns.",
                    entity_type, matches
                ),
            )
        } else {
            (
                false,
                format!(
                    "[Match] None of the {}s '{:?}' match any of the patterns.",
                    entity_type, path_context
                ),
            )
        }
    }
}
