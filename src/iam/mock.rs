// use std::collections::HashMap;

// use crate::iam::{
//     policy::Evaluate,
//     types::{Effect, Group, TrustPolicy},
// };

// use super::types::{Condition, Operator, Policy, Statement};

// fn mock_policies(policy_name: &str) -> Vec<Policy> {
//     let condition = Condition {
//         operator: Operator::Eq,
//         key: "user_name".to_string(),
//         value: "alice".to_string(),
//     };

//     let statement = Statement {
//         sid: "some_id".to_string(),
//         effect: Effect::Allow,
//         action: vec!["project1:write".to_string(), "project1:read".to_string()],
//         not_action: vec![],
//         resource: vec![
//             "link:koddly:documents:/v_a".to_string(),
//             "link:koddly:documents:/project1/*".to_string(),
//             "link:koddly:documents:/*/revision/*".to_string(),
//         ],
//         not_resource: vec![],
//         principal: vec![],
//         not_principal: vec![],
//         condition: vec![condition],
//     };

//     let statement_deny = Statement {
//         sid: "some_id1".to_string(),
//         effect: Effect::Deny,
//         action: vec!["project1:delete".to_string(), "project1:update".to_string()],
//         not_action: vec![],
//         resource: vec!["link:koddly:documents:/project1/*".to_string()],
//         not_resource: vec![],
//         principal: vec![],
//         not_principal: vec![],
//         condition: vec![],
//     };

//     return vec![Policy {
//         version: "2012-10-17".to_string(),
//         policy_name: policy_name.to_string(),
//         statements: vec![statement, statement_deny],
//     }];
// }

// pub fn mock_data() -> Evaluate {
//     let trust_policy_example = TrustPolicy {
//         version: "2023-01-01".to_string(),
//         statements: vec![Statement {
//             sid: "Stmt12345".to_string(),
//             effect: Effect::Allow,
//             principal: vec!["alice".to_string()],
//             not_principal: vec![],
//             action: vec![],
//             not_action: vec![],
//             resource: vec![],
//             not_resource: vec![],
//             condition: vec![
//                 Condition {
//                     operator: Operator::Eq,
//                     key: "department".to_string(),
//                     value: "finance".to_string(),
//                 },
//                 Condition {
//                     operator: Operator::Eq,
//                     key: "user_name".to_string(),
//                     value: "alice".to_string(),
//                 },
//                 Condition {
//                     operator: Operator::Eq,
//                     key: "role_name".to_string(),
//                     value: "role1".to_string(),
//                 },
//                 Condition {
//                     operator: Operator::Eq,
//                     key: "group_name".to_string(),
//                     value: "group1".to_string(),
//                 },
//             ],
//         }],
//     };

//     let context = Evaluate {
//         action: vec!["project1:read".to_string(), "project1:write".to_string()],
//         resource: vec![
//             "link:koddly:documents:/project1/".to_string(),
//             "link:koddly:documents:/project2/revision".to_string(),
//         ],
//         principal: HashMap::new(),
//         context: {
//             let mut context = HashMap::new();
//             context.insert("department".to_string(), vec!["finance".to_string()]);
//             context.insert("user_name".to_string(), vec!["alice".to_string()]);
//             context
//         },
//         policies: vec![],
//         groups: vec![Group {
//             group_name: "group1".to_string(),
//             policies: mock_policies("policy11"),
//             trust_policy: Some(trust_policy_example),
//         }],
//         roles: vec![],
//     };

//     return context;
// }
