#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use crate::iam::{
        policy::{Evaluate, EvaluateContextBuilder},
        types::{Condition, Effect, Group, Operator, Policy, Role, Statement, TrustPolicy},
    };

    // fn get_test_context() -> EvaluateContextBuilder {
    //     let context = EvaluateContext {
    //         action: vec![],
    //         resource: vec![],
    //         principal: HashMap::new(),
    //         context: HashMap::new(),
    //         policies: vec![],
    //         roles: vec![],
    //         groups: vec![],
    //     };

    //     EvaluateContextBuilder::init_context(&context)
    // }

    fn get_test_context() -> Evaluate {
        Evaluate {
            action: vec![],
            resource: vec![],
            principal: HashMap::new(),
            context: HashMap::new(),
            policies: vec![],
            roles: vec![],
            groups: vec![],
        }
    }

    // Basic Policy Evaluation
    #[test]
    fn user_with_no_policies_roles_or_groups() {
        let context = get_test_context();

        let builder = EvaluateContextBuilder::init_context(&context);

        // Ahora puedes usar los métodos de EvaluateContextBuilder
        let result = builder.evaluate_user_policies();

        assert_eq!(result.0, false);
        assert_eq!(
            result.1,
            "[Groups, Roles, Policies] User doesn't have any groups, roles, policies"
        );
    }

    #[test]
    fn user_with_only_policies() {
        // Primero, obtenemos el EvaluateContext para pruebas
        let mut ctx = get_test_context();

        // Configuramos el EvaluateContext
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string(), "project1:read".to_string()],
                not_action: vec![],
                resource: vec![
                    "link:koddly:documents:/v_a".to_string(),
                    "link:koddly:documents:/project1/*".to_string(),
                    "link:koddly:documents:/*/revision/*".to_string(),
                ],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                condition: vec![Condition {
                    operator: Operator::Eq,
                    key: "user_name".to_string(),
                    value: "alice".to_string(),
                }],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });

        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());

        // Ahora, inicializamos el EvaluateContextBuilder con el EvaluateContext que hemos configurado
        let builder = EvaluateContextBuilder::init_context(&ctx);

        // Finalmente, evaluamos las políticas usando el builder
        let result = builder.evaluate_user_policies();

        // ... verifica el resultado esperado basado en la política que añadiste
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    #[test]
    fn user_with_only_groups() {
        let mut context = get_test_context();
        context.groups.push(Group {
            group_name: "test".to_string(),
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: Vec::new(),
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: Vec::new(),
                    not_resource: Vec::new(),
                    principal: Vec::new(),
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: None,
        });
        context
            .context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        context.action.push("project1:write".to_string());
        context
            .resource
            .push("link:koddly:documents:/project1/1234".to_string());

        // Crear EvaluateContextBuilder con el contexto
        let builder = EvaluateContextBuilder::init_context(&context);
        // Evaluar políticas de usuario
        let result = builder.evaluate_user_policies();

        println!("result: {:?}", result);
        // Verificar que el resultado sea el esperado
        assert_eq!(result.0, true);
    }

    #[test]
    fn user_with_only_roles() {
        let mut context = get_test_context();
        context.roles.push(Role {
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: Vec::new(),
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: Vec::new(),
                    not_resource: Vec::new(),
                    principal: Vec::new(),
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: Some(TrustPolicy {
                version: "2023-01-01".to_string(),
                statements: vec![Statement {
                    sid: "Stmt12345".to_string(),
                    effect: Effect::Allow,
                    principal: vec!["alice".to_string()],
                    not_principal: Vec::new(),
                    action: Vec::new(),
                    not_action: Vec::new(),
                    resource: Vec::new(),
                    not_resource: Vec::new(),
                    condition: vec![
                        Condition {
                            operator: Operator::Eq,
                            key: "department".to_string(),
                            value: "finance".to_string(),
                        },
                        Condition {
                            operator: Operator::Eq,
                            key: "user_name".to_string(),
                            value: "alice".to_string(),
                        },
                    ],
                }],
            }),
        });
        context
            .context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        context
            .context
            .insert("department".to_string(), vec!["finance".to_string()]);
        context
            .context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        context.action.push("project1:write".to_string());
        context
            .resource
            .push("link:koddly:documents:/project1/1234".to_string());

        let builder = EvaluateContextBuilder::init_context(&context);
        let result = builder.evaluate_user_policies();

        println!("result: {:?}", result);
        assert_eq!(result.0, true); // Ajustar según la lógica de evaluación de la política
    }

    #[test]
    fn user_with_combinations() {
        let mut ctx = get_test_context();
        ctx.roles.push(Role {
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: Some(TrustPolicy {
                version: "2023-01-01".to_string(),
                statements: vec![Statement {
                    sid: "Stmt12345".to_string(),
                    effect: Effect::Allow,
                    principal: vec!["alice".to_string()],
                    not_principal: vec![],
                    action: vec![],
                    not_action: vec![],
                    resource: vec![],
                    not_resource: vec![],
                    condition: vec![
                        Condition {
                            operator: Operator::Eq,
                            key: "department".to_string(),
                            value: "finance".to_string(),
                        },
                        Condition {
                            operator: Operator::Eq,
                            key: "user_name".to_string(),
                            value: "alice".to_string(),
                        },
                    ],
                }],
            }),
        });
        ctx.groups.push(Group {
            group_name: "test".to_string(),
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: None,
        });
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string(), "project1:read".to_string()],
                not_action: vec![],
                resource: vec![
                    "link:koddly:documents:/v_a".to_string(),
                    "link:koddly:documents:/project1/*".to_string(),
                    "link:koddly:documents:/*/revision/*".to_string(),
                ],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                condition: vec![Condition {
                    operator: Operator::Eq,
                    key: "user_name".to_string(),
                    value: "alice".to_string(),
                }],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());

        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the combination
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Effect Handling
    #[test]
    fn policy_with_allow_effect() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string(), "project1:read".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec![
                    "link:koddly:documents:/v_a".to_string(),
                    "link:koddly:documents:/project1/*".to_string(),
                    "link:koddly:documents:/*/revision/*".to_string(),
                ],
                condition: vec![Condition {
                    operator: Operator::Eq,
                    key: "user_name".to_string(),
                    value: "alice".to_string(),
                }],
                sid: "some_id".to_string(),
            }],
            policy_name: "test".to_string(),
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the Allow effect
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    #[test]
    fn policy_with_deny_effect() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            version: "2012-10-17".to_string(),
            statements: vec![Statement {
                effect: Effect::Deny,
                action: vec!["project1:write".to_string(), "project1:read".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec![
                    "link:koddly:documents:/v_a".to_string(),
                    "link:koddly:documents:/project1/*".to_string(),
                    "link:koddly:documents:/*/revision/*".to_string(),
                ],
                condition: vec![Condition {
                    operator: Operator::Eq,
                    key: "user_name".to_string(),
                    value: "alice".to_string(),
                }],
                sid: "some_id".to_string(),
            }],
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the Deny effect
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(
            result.1,
            "[Deny] Policy has complete required attributes and is denied"
        );
    }

    // Statement Matching
    // Test with a user requesting an action not mentioned in any policy.
    #[test]
    fn policy_with_no_actions() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            version: "2012-10-17".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec![],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec![],
                condition: vec![],
                sid: "some_id".to_string(),
            }],
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the Deny effect
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
    }

    // Test with a user requesting an action that is explicitly allowed by a policy.
    #[test]
    fn policy_with_matching_actions() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            version: "2012-10-17".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project1/*".to_string()],
                condition: vec![],
                sid: "some_id".to_string(),
            }],
        });
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the Deny effect
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Test with a user requesting an action that is explicitly denied by a policy.
    #[test]
    fn policy_with_non_matching_actions() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            version: "2012-10-17".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project1/*".to_string()],
                condition: vec![],
                sid: "some_id".to_string(),
            }],
        });
        ctx.action.push("project1:read".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the Deny effect
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(
            result.1,
            "[Match] None of the actions '[\"project1:read\"]' match any of the patterns."
        );
    }

    // Resource Pattern Matching
    // Test with resources that match patterns in the policy.
    #[test]
    fn policy_with_matching_resources() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            version: "2012-10-17".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project1/*".to_string()],
                condition: vec![],
                sid: "some_id".to_string(),
            }],
        });
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the Deny effect
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Test with resources that don't match any pattern in the policy.
    #[test]
    fn policy_with_non_matching_resources() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            version: "2012-10-17".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project2/*".to_string()],
                condition: vec![],
                sid: "some_id".to_string(),
            }],
        });
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the Deny effect
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(
            result.1,
            "[Match] None of the resources '[\"link:koddly:documents:/project1/1234\"]' match any of the patterns."
        );
    }

    // Test with incorrect or malformed patterns.
    #[test]
    fn policy_with_malformed_resources() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            version: "2012-10-17".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project1/*".to_string()],
                condition: vec![],
                sid: "some_id".to_string(),
            }],
        });
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        // ... check the expected result based on the Deny effect
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Action Pattern Matching
    // Similar to the resource pattern tests, but for actions.
    #[test]
    fn policy_with_matching_actions2() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project1/*".to_string()],
                condition: vec![],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Condition Evaluation
    // Test with policies that have no conditions.
    #[test]
    fn policy_with_no_conditions() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project1/*".to_string()],
                condition: vec![],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Test with conditions using the Eq operator that are met.
    #[test]
    fn policy_with_matching_eq_conditions() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project1/*".to_string()],
                condition: vec![
                    Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    },
                    Condition {
                        operator: Operator::Eq,
                        key: "department".to_string(),
                        value: "finance".to_string(),
                    },
                ],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Test with conditions using the Eq operator that are not met.
    #[test]
    fn policy_with_non_matching_eq_conditions() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string()],
                not_action: vec![],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                resource: vec!["link:koddly:documents:/project1/*".to_string()],
                condition: vec![
                    Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    },
                    Condition {
                        operator: Operator::Eq,
                        key: "department".to_string(),
                        value: "finance".to_string(),
                    },
                ],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["bob".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(
            result.1,
            "[Condition] User doesn't have required attribute user_name equals alice"
        );
    }

    // Role Evaluation
    // Test assuming a role without any trust policy.
    #[test]
    fn role_with_no_trust_policy() {
        let mut ctx = get_test_context();
        ctx.roles.push(Role {
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: None,
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());

        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(result.1, "[Trust policy] Role doesn't have trust policy");
    }

    // Test assuming a role with a trust policy that doesn't match the user's attributes.
    #[test]
    fn role_with_non_matching_trust_policy() {
        let mut ctx = get_test_context();
        ctx.roles.push(Role {
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "bob".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: Some(TrustPolicy {
                version: "2023-01-01".to_string(),
                statements: vec![Statement {
                    sid: "Stmt12345".to_string(),
                    effect: Effect::Allow,
                    principal: vec!["alice".to_string()],
                    not_principal: vec![],
                    action: vec![],
                    not_action: vec![],
                    resource: vec![],
                    not_resource: vec![],
                    condition: vec![
                        Condition {
                            operator: Operator::Eq,
                            key: "department".to_string(),
                            value: "finance".to_string(),
                        },
                        Condition {
                            operator: Operator::Eq,
                            key: "user_name".to_string(),
                            value: "alice".to_string(),
                        },
                    ],
                }],
            }),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());

        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(
            result.1,
            "[Condition] User doesn't have required attribute user_name equals bob"
        );
    }

    // Test assuming a role with a trust policy that matches the user's attributes.
    #[test]
    fn role_with_matching_trust_policy() {
        let mut ctx = get_test_context();
        ctx.roles.push(Role {
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: Some(TrustPolicy {
                version: "2023-01-01".to_string(),
                statements: vec![Statement {
                    sid: "Stmt12345".to_string(),
                    effect: Effect::Allow,
                    principal: vec!["alice".to_string()],
                    not_principal: vec![],
                    action: vec![],
                    not_action: vec![],
                    resource: vec![],
                    not_resource: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "department".to_string(),
                        value: "finance".to_string(),
                    }],
                }],
            }),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());

        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Test with roles having policies and evaluate if they are correctly applied.
    #[test]
    fn role_with_policies() {
        let mut ctx = get_test_context();
        ctx.roles.push(Role {
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: Some(TrustPolicy {
                version: "2023-01-01".to_string(),
                statements: vec![Statement {
                    sid: "Stmt12345".to_string(),
                    effect: Effect::Allow,
                    principal: vec!["alice".to_string()],
                    not_principal: vec![],
                    action: vec![],
                    not_action: vec![],
                    resource: vec![],
                    not_resource: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "department".to_string(),
                        value: "finance".to_string(),
                    }],
                }],
            }),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());

        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Group Evaluation
    // Test with a user who is a member of a group with policies.
    #[test]
    fn group_with_policies() {
        let mut ctx = get_test_context();
        ctx.groups.push(Group {
            group_name: "test".to_string(),
            policies: vec![Policy {
                policy_name: "test".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: None,
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());

        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Test with a user who is a member of multiple groups with different policies.
    #[test]
    fn multiple_groups_with_policies() {
        let mut ctx = get_test_context();
        ctx.groups.push(Group {
            group_name: "test".to_string(),
            policies: vec![Policy {
                policy_name: "test_policy_group".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_a".to_string(),
                        "link:koddly:documents:/project1/*".to_string(),
                        "link:koddly:documents:/*/revision/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "alice".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: None,
        });
        ctx.groups.push(Group {
            group_name: "test_group2".to_string(),
            policies: vec![Policy {
                policy_name: "test2".to_string(),
                statements: vec![Statement {
                    effect: Effect::Allow,
                    action: vec!["project2:write".to_string(), "project2:read".to_string()],
                    not_action: vec![],
                    resource: vec![
                        "link:koddly:documents:/v_b".to_string(),
                        "link:koddly:documents:/project2/*".to_string(),
                        "link:koddly:documents:/*/revision1/*".to_string(),
                    ],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![Condition {
                        operator: Operator::Eq,
                        key: "user_name".to_string(),
                        value: "bob".to_string(),
                    }],
                    sid: "some_id".to_string(),
                }],
                version: "2012-10-17".to_string(),
            }],
            trust_policy: None,
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project2:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project2/1234".to_string());

        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Error Scenarios
    // Test with malformed patterns to see if the system correctly handles errors.
    #[test]
    fn malformed_patterns() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string(), "project1:read".to_string()],
                not_action: vec![],
                resource: vec![
                    "link:koddly:documents:/v_a".to_string(),
                    "link:koddly:documents:/project1/*".to_string(),
                    "link:koddly:documents:/*/revision/*".to_string(),
                ],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                condition: vec![Condition {
                    operator: Operator::Eq,
                    key: "user_name".to_string(),
                    value: "alice".to_string(),
                }],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:[documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(
            result.1,
            "[Match] None of the resources '[\"link:koddly:[documents:/project1/1234\"]' match any of the patterns."
        );
    }

    // Test with unsupported operators in conditions.
    #[test]
    fn unsupported_operators() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string(), "project1:read".to_string()],
                not_action: vec![],
                resource: vec![
                    "link:koddly:documents:/v_a".to_string(),
                    "link:koddly:documents:/project1/*".to_string(),
                    "link:koddly:documents:/*/revision/*".to_string(),
                ],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                condition: vec![Condition {
                    operator: Operator::Neq,
                    key: "user_name".to_string(),
                    value: "alice".to_string(),
                }],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:[documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(result.1, "[Condition] Unsupported operator");
    }

    // Glob Pattern Tests
    // Test with simple and complex glob patterns.
    #[test]
    fn glob_pattern_matching() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string(), "project1:read".to_string()],
                not_action: vec![],
                resource: vec![
                    "link:koddly:documents:/v_a".to_string(),
                    "link:koddly:documents:/project1/*".to_string(),
                    "link:koddly:documents:/*/revision/*".to_string(),
                ],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                condition: vec![Condition {
                    operator: Operator::Eq,
                    key: "user_name".to_string(),
                    value: "alice".to_string(),
                }],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Test with edge cases like patterns with only wildcards.
    #[test]
    fn glob_pattern_matching_edge_cases() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test".to_string(),
            statements: vec![Statement {
                effect: Effect::Allow,
                action: vec!["project1:write".to_string(), "project1:read".to_string()],
                not_action: vec![],
                resource: vec!["*".to_string()],
                not_principal: vec![],
                not_resource: vec![],
                principal: vec![],
                condition: vec![Condition {
                    operator: Operator::Eq,
                    key: "user_name".to_string(),
                    value: "alice".to_string(),
                }],
                sid: "some_id".to_string(),
            }],
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.context
            .insert("department".to_string(), vec!["finance".to_string()]);
        ctx.context
            .insert("role_name".to_string(), vec!["role1".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, true);
    }

    // Order of Evaluation
    // Given that IAM systems typically evaluate Deny before Allow, ensure that the order of statements in a policy, or the order of policies themselves, does not affect the outcome.
    #[test]
    fn order_of_evaluation() {
        let mut ctx = get_test_context();
        ctx.policies.push(Policy {
            policy_name: "test1".to_string(),
            statements: vec![
                Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec!["*".to_string()],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![],
                    sid: "some_id".to_string(),
                },
                Statement {
                    effect: Effect::Deny,
                    action: vec!["project1:write".to_string()],
                    not_action: vec![],
                    resource: vec!["*".to_string()],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![],
                    sid: "some_id".to_string(),
                },
            ],
            version: "2012-10-17".to_string(),
        });
        ctx.policies.push(Policy {
            policy_name: "test2".to_string(),
            statements: vec![
                Statement {
                    effect: Effect::Deny,
                    action: vec!["project1:write".to_string()],
                    not_action: vec![],
                    resource: vec!["*".to_string()],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![],
                    sid: "some_id".to_string(),
                },
                Statement {
                    effect: Effect::Allow,
                    action: vec!["project1:write".to_string(), "project1:read".to_string()],
                    not_action: vec![],
                    resource: vec!["*".to_string()],
                    not_principal: vec![],
                    not_resource: vec![],
                    principal: vec![],
                    condition: vec![],
                    sid: "some_id".to_string(),
                },
            ],
            version: "2012-10-17".to_string(),
        });
        ctx.context
            .insert("user_name".to_string(), vec!["alice".to_string()]);
        ctx.action.push("project1:write".to_string());
        ctx.resource
            .push("link:koddly:documents:/project1/1234".to_string());
        let builder = EvaluateContextBuilder::init_context(&ctx);
        let result = builder.evaluate_user_policies();
        println!("result: {:?}", result);
        assert_eq!(result.0, false);
        assert_eq!(
            result.1,
            "[Deny] Policy has complete required attributes and is denied"
        );
    }
}
