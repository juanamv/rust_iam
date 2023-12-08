pub mod iam;
mod test;

use crate::iam::policy::EvaluateContextBuilder;
use iam::policy::Evaluate;

/// Evalúa las políticas asociadas a un usuario, basado en el contexto proporcionado por una estructura `Evaluate`.
///
/// Esta función es el punto de entrada para realizar una evaluación comprensiva de las políticas de usuario,
/// incluyendo la verificación de políticas, roles y grupos. Determina si un conjunto de acciones y recursos
/// especificados en `data` están permitidos o denegados según las políticas aplicables.
///
/// # Argumentos
/// * `data` - Una instancia de `Evaluate` que contiene las acciones, recursos, y políticas, roles y grupos
///   asociados para realizar la evaluación.
///
/// # Devuelve
/// Una tupla `(bool, String)`. El primer elemento (`bool`) indica si las acciones y recursos están permitidos
/// (`true`) o denegados (`false`). El segundo elemento (`String`) proporciona un mensaje detallado del resultado.
///
/// # Ejemplos
/// Supongamos que tienes un conjunto de acciones y recursos específicos que deseas evaluar,
/// junto con un conjunto de políticas, roles y grupos definidos para un usuario. Aquí se muestra cómo
/// podrías crear una instancia de `Evaluate` y usar la función `evaluate` para determinar si las acciones
/// y recursos están permitidos para ese usuario:
///
/// ```
/// use crate::iam::policy::{Evaluate, EvaluateContextBuilder, Policy, Role, Group};
/// use std::collections::HashMap;
///
/// // Creación de un ejemplo de políticas, roles y grupos
/// let policies = vec![Policy { /* ... inicialización de la política ... */ }];
/// let roles = vec![Role { /* ... inicialización del rol ... */ }];
/// let groups = vec![Group { /* ... inicialización del grupo ... */ }];
///
/// // Creación de la instancia de Evaluate con datos específicos
/// let data = Evaluate {
///     action: vec!["accion1".to_string(), "accion2".to_string()],
///     resource: vec!["recurso1".to_string(), "recurso2".to_string()],
///     principal: HashMap::new(), // Inicialización del principal si es necesario
///     context: HashMap::new(), // Inicialización del contexto si es necesario
///     policies,
///     roles,
///     groups,
/// };
///
/// // Uso de la función evaluate
/// let resultado = evaluate(data);
/// println!("Permisos: {}, Mensaje: {}", resultado.0, resultado.1);
/// ```
///
/// Este ejemplo crea una instancia de `Evaluate` con listas de acciones y recursos, así como con
/// conjuntos de políticas, roles y grupos. Luego, utiliza la función `evaluate` para obtener el resultado de
/// la evaluación de estas políticas.
/// # Errores y Validaciones
/// La función no maneja errores internos y asume que la estructura `Evaluate` proporcionada está bien formada.
/// Cualquier inconsistencia en los datos de entrada podría afectar los resultados de la evaluación.
///
/// # Consideraciones
/// - La exactitud y coherencia de los datos en la instancia `Evaluate` son críticas para el resultado correcto.
/// - La función depende de `EvaluateContextBuilder` para el procesamiento de políticas, por lo que cualquier cambio
///   en la lógica de `EvaluateContextBuilder` puede afectar el comportamiento de `evaluate`.
pub fn evaluate(data: Evaluate) -> (bool, String) {
    let validate: (bool, String) =
        EvaluateContextBuilder::init_context(&data).evaluate_user_policies();
    return validate;
}
