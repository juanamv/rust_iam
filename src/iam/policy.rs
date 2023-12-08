use std::collections::HashMap;

use super::types::{Group, Policy, Role};

/// `Evaluate` es una estructura que representa el contexto para la evaluación de permisos.
/// Contiene todas las acciones, recursos, principios y contextos necesarios para evaluar las políticas,
/// roles y grupos aplicables a un usuario o entidad.
///
/// # Campos
/// - `action`: Un vector de `String` que representa las acciones a evaluar.
/// - `resource`: Un vector de `String` que representa los recursos involucrados en la evaluación.
/// - `principal`: Un `HashMap<String, String>` que mapea identificadores de entidades con sus atributos.
/// - `context`: Un `HashMap<String, Vec<String>>` que proporciona información adicional relevante para la evaluación.
/// - `policies`: Un vector de `Policy` que contiene las políticas aplicables.
/// - `roles`: Un vector de `Role` que representa los roles asociados con el contexto.
/// - `groups`: Un vector de `Group` que representa los grupos asociados con el contexto.
///
/// # Uso
/// Esta estructura se utiliza para reunir toda la información relevante necesaria para evaluar
/// las políticas de acceso y permisos en un determinado contexto.
#[derive(Debug, Clone)]
pub struct Evaluate {
    pub action: Vec<String>,
    pub resource: Vec<String>,
    pub principal: HashMap<String, String>,
    pub context: HashMap<String, Vec<String>>,
    pub policies: Vec<Policy>,
    pub roles: Vec<Role>,
    pub groups: Vec<Group>,
}

/// `EvaluateContextBuilder` es una estructura utilizada para construir y evaluar un contexto de evaluación `Evaluate`.
/// Proporciona funcionalidades para evaluar permisos basados en políticas, roles y grupos.
///
/// # Campos
/// - `context`: Una instancia de `Evaluate` que representa el contexto de evaluación actual.
/// - `all_deny_statements_resource`: Un vector de `String` que contiene todos los recursos mencionados en las declaraciones de tipo 'Deny'.
/// - `all_allow_statements_resource`: Un vector de `String` que contiene todos los recursos mencionados en las declaraciones de tipo 'Allow'.
/// - `all_deny_statements_action`: Un vector de `String` que contiene todas las acciones mencionadas en las declaraciones de tipo 'Deny'.
/// - `all_allow_statements_action`: Un vector de `String` que contiene todas las acciones mencionadas en las declaraciones de tipo 'Allow'.
///
/// # Uso
/// Esta estructura se utiliza para inicializar y manejar el proceso de evaluación de políticas,
/// permitiendo determinar si se conceden o deniegan permisos específicos en función del contexto proporcionado.
#[derive(Debug, Clone)]
pub struct EvaluateContextBuilder {
    pub context: Evaluate,
    pub all_deny_statements_resource: Vec<String>,
    pub all_allow_statements_resource: Vec<String>,
    pub all_deny_statements_action: Vec<String>,
    pub all_allow_statements_action: Vec<String>,
}
