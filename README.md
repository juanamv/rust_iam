# RustIAM

## Descripción

`RustIAM` es un paquete de Rust diseñado para practicar y demostrar conceptos similares a los de AWS IAM (Identity and Access Management). Este paquete implementa funcionalidades básicas para evaluar políticas, roles y grupos en un contexto de control de acceso. Es importante destacar que `RustIAM` es un proyecto de práctica y no debe usarse en entornos de producción.

## Advertencia

Este paquete es exclusivamente para fines educativos y de práctica. **No se recomienda su uso en aplicaciones de producción** debido a que no ha sido probado exhaustivamente y podría contener errores o vulnerabilidades de seguridad.

## Características

- Evaluación de políticas de acceso similares a las de AWS IAM.
- Soporte para roles y grupos en la gestión de políticas.
- Manejo de permisos y atributos detallados.

## Uso

El siguiente es un ejemplo de cómo utilizar `RustIAM` para evaluar si un conjunto de acciones y recursos están permitidos bajo una serie de políticas:

```rust
use rust_iam::{Evaluate, EvaluateContextBuilder, Policy, Statement, Effect, Condition, Operator};

// Creación de políticas de ejemplo
let policy = Policy {
    version: "2022-01-01".to_string(),
    policy_name: "ExamplePolicy".to_string(),
    statements: vec![Statement {
        sid: "ExampleStatement".to_string(),
        effect: Effect::Allow,
        condition: vec![Condition {
            operator: Operator::Eq,
            key: "exampleKey".to_string(),
            value: "exampleValue".to_string(),
        }],
    }],
};

// Crear un contexto de evaluación
let data = Evaluate {
    action: vec!["some_action".to_string()],
    resource: vec!["some_resource".to_string()],
    policies: vec![policy],
    roles: vec![],
    groups: vec![],
};

// Inicializa y evalúa las políticas
let builder = EvaluateContextBuilder::init_context(&data);
let result = builder.evaluate_user_policies();
println!("Evaluación: {:?}", result);
```

## Contribuciones

Las contribuciones a `RustIAM` son bienvenidas, especialmente para mejorar y expandir sus capacidades. Si tienes sugerencias, correcciones o nuevas funcionalidades, no dudes en contribuir a través de pull requests o issues.

## Licencia

Este proyecto se encuentra bajo la Licencia MIT. Para más información, consulta el archivo [LICENSE](LICENSE).
