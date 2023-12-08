use serde::{Deserialize, Serialize};

/// Representa una política de confianza, que define condiciones bajo las cuales un rol o grupo es confiable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicy {
    pub version: String,
    pub statements: Vec<Statement>,
}

/// Define un rol que puede incluir múltiples políticas y una política de confianza opcional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub policies: Vec<Policy>,
    pub trust_policy: Option<TrustPolicy>,
}

/// Representa un grupo, que puede contener múltiples políticas y una política de confianza opcional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub group_name: String,
    pub policies: Vec<Policy>,
    pub trust_policy: Option<TrustPolicy>,
}

/// Define una política, que incluye un conjunto de declaraciones que especifican permisos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: String,
    pub policy_name: String,
    pub statements: Vec<Statement>,
}

/// Enumera los diferentes operadores que pueden ser usados en condiciones de políticas.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operator {
    Eq,  // Equal
    Ne,  // Not equal
    Lt,  // Less than
    Le,  // Less than or equal
    Gt,  // Greater than
    Ge,  // Greater than or equal
    And, // Logical and
    Or,  // Logical or
    Not, // Logical not
    Neq, // Unsupported operator
}

/// Define una condición utilizada en las declaraciones de políticas, basada en un operador y un par clave-valor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub operator: Operator,
    pub key: String,
    pub value: String,
}

/// Representa el efecto de una declaración de política, permitiendo o denegando el acceso.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

impl PartialEq for Effect {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Effect::Allow, Effect::Allow) => true,
            (Effect::Deny, Effect::Deny) => true,
            _ => false,
        }
    }
}

/// Representa una declaración individual dentro de una política, especificando permisos o restricciones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    pub sid: String,
    pub effect: Effect,
    pub principal: Vec<String>,
    pub not_principal: Vec<String>,
    pub action: Vec<String>,
    pub not_action: Vec<String>,
    pub resource: Vec<String>,
    pub not_resource: Vec<String>,
    pub condition: Vec<Condition>,
}

/// Define los posibles resultados de una evaluación de políticas, indicando si se permite o deniega una acción.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvaluationResult {
    Allowed(String),
    Denied(String),
}
