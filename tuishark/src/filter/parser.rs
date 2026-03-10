/// Tokenizer and recursive descent parser for filter expressions.
///
/// Grammar:
///   expr     = or_expr
///   or_expr  = and_expr (("or" | "||") and_expr)*
///   and_expr = not_expr (("and" | "&&") not_expr)*
///   not_expr = ("not" | "!") not_expr | primary
///   primary  = "(" expr ")" | comparison | contains
///   comparison = field compare_op value
///   contains   = field "contains" quoted_string
///   field    = "ip.src" | "ip.dst" | "ip.addr" | "port.src" | "port.dst" | "port" | "proto" | "len" | "info"
///   compare_op = "==" | "!=" | ">" | "<" | ">=" | "<="
///   value    = integer | string

use super::ast::{CompareOp, Expr, Field, Value};

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Field(Field),
    Op(CompareOp),
    Contains,
    And,
    Or,
    Not,
    LParen,
    RParen,
    Str(String),
    Int(u64),
}

pub fn parse(input: &str) -> Result<Expr, String> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err("empty filter expression".into());
    }
    let mut pos = 0;
    let expr = parse_or(&tokens, &mut pos)?;
    if pos < tokens.len() {
        return Err(format!("unexpected token at position {pos}"));
    }
    Ok(expr)
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Skip whitespace
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }

        // Parentheses
        if chars[i] == '(' {
            tokens.push(Token::LParen);
            i += 1;
            continue;
        }
        if chars[i] == ')' {
            tokens.push(Token::RParen);
            i += 1;
            continue;
        }

        // Two-char operators
        if i + 1 < chars.len() {
            match (chars[i], chars[i + 1]) {
                ('=', '=') => { tokens.push(Token::Op(CompareOp::Eq)); i += 2; continue; }
                ('!', '=') => { tokens.push(Token::Op(CompareOp::Ne)); i += 2; continue; }
                ('>', '=') => { tokens.push(Token::Op(CompareOp::Ge)); i += 2; continue; }
                ('<', '=') => { tokens.push(Token::Op(CompareOp::Le)); i += 2; continue; }
                ('&', '&') => { tokens.push(Token::And); i += 2; continue; }
                ('|', '|') => { tokens.push(Token::Or); i += 2; continue; }
                _ => {}
            }
        }

        // Single-char operators
        match chars[i] {
            '>' => { tokens.push(Token::Op(CompareOp::Gt)); i += 1; continue; }
            '<' => { tokens.push(Token::Op(CompareOp::Lt)); i += 1; continue; }
            '!' => { tokens.push(Token::Not); i += 1; continue; }
            _ => {}
        }

        // Quoted string
        if chars[i] == '"' {
            i += 1;
            let start = i;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err("unterminated string".into());
            }
            let s: String = chars[start..i].iter().collect();
            tokens.push(Token::Str(s));
            i += 1; // skip closing quote
            continue;
        }

        // Word or number
        if chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let lower = word.to_ascii_lowercase();

            // Try as keyword/field
            match lower.as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                "contains" => tokens.push(Token::Contains),
                "ip.src" => tokens.push(Token::Field(Field::IpSrc)),
                "ip.dst" => tokens.push(Token::Field(Field::IpDst)),
                "ip.addr" => tokens.push(Token::Field(Field::IpAddr)),
                "port.src" => tokens.push(Token::Field(Field::PortSrc)),
                "port.dst" => tokens.push(Token::Field(Field::PortDst)),
                "port" => tokens.push(Token::Field(Field::Port)),
                "proto" => tokens.push(Token::Field(Field::Proto)),
                "len" => tokens.push(Token::Field(Field::Len)),
                "info" => tokens.push(Token::Field(Field::Info)),
                _ => {
                    // Try as integer
                    if let Ok(n) = word.parse::<u64>() {
                        tokens.push(Token::Int(n));
                    } else {
                        // Unquoted string value (e.g., protocol name, IP address)
                        tokens.push(Token::Str(word));
                    }
                }
            }
            continue;
        }

        return Err(format!("unexpected character: '{}'", chars[i]));
    }

    Ok(tokens)
}

fn parse_or(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    let mut left = parse_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == Token::Or {
        *pos += 1;
        let right = parse_and(tokens, pos)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    let mut left = parse_not(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == Token::And {
        *pos += 1;
        let right = parse_not(tokens, pos)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_not(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    if *pos < tokens.len() && tokens[*pos] == Token::Not {
        *pos += 1;
        let expr = parse_not(tokens, pos)?;
        return Ok(Expr::Not(Box::new(expr)));
    }
    parse_primary(tokens, pos)
}

fn parse_primary(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    if *pos >= tokens.len() {
        return Err("unexpected end of expression".into());
    }

    // Parenthesized expression
    if tokens[*pos] == Token::LParen {
        *pos += 1;
        let expr = parse_or(tokens, pos)?;
        if *pos >= tokens.len() || tokens[*pos] != Token::RParen {
            return Err("missing closing parenthesis".into());
        }
        *pos += 1;
        return Ok(expr);
    }

    // Must be a field comparison or contains
    let field = match &tokens[*pos] {
        Token::Field(f) => f.clone(),
        other => return Err(format!("expected field name, got {other:?}")),
    };
    *pos += 1;

    if *pos >= tokens.len() {
        return Err("expected operator after field".into());
    }

    // Contains
    if tokens[*pos] == Token::Contains {
        *pos += 1;
        if *pos >= tokens.len() {
            return Err("expected value after 'contains'".into());
        }
        let value = match &tokens[*pos] {
            Token::Str(s) => s.to_ascii_lowercase(),
            Token::Int(n) => n.to_string(),
            other => return Err(format!("expected string after 'contains', got {other:?}")),
        };
        *pos += 1;
        return Ok(Expr::Contains { field, value });
    }

    // Comparison
    let op = match &tokens[*pos] {
        Token::Op(op) => op.clone(),
        other => return Err(format!("expected operator, got {other:?}")),
    };
    *pos += 1;

    if *pos >= tokens.len() {
        return Err("expected value after operator".into());
    }

    let value = match &tokens[*pos] {
        Token::Str(s) => Value::Str(s.clone()),
        Token::Int(n) => Value::Int(*n),
        other => return Err(format!("expected value, got {other:?}")),
    };
    *pos += 1;

    Ok(Expr::Compare { field, op, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_eq() {
        let expr = parse("proto == tcp").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::Proto,
                op: CompareOp::Eq,
                value: Value::Str("tcp".into()),
            }
        );
    }

    #[test]
    fn parse_ip_addr() {
        let expr = parse("ip.src == 192.168.1.1").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::IpSrc,
                op: CompareOp::Eq,
                value: Value::Str("192.168.1.1".into()),
            }
        );
    }

    #[test]
    fn parse_port_int() {
        let expr = parse("port == 443").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::Port,
                op: CompareOp::Eq,
                value: Value::Int(443),
            }
        );
    }

    #[test]
    fn parse_and_or() {
        let expr = parse("proto == tcp and port == 80").unwrap();
        assert!(matches!(expr, Expr::And(_, _)));
    }

    #[test]
    fn parse_not() {
        let expr = parse("not proto == arp").unwrap();
        assert!(matches!(expr, Expr::Not(_)));
    }

    #[test]
    fn parse_contains() {
        let expr = parse("info contains \"SYN\"").unwrap();
        assert_eq!(
            expr,
            Expr::Contains {
                field: Field::Info,
                value: "syn".into(), // pre-lowercased at parse time
            }
        );
    }

    #[test]
    fn parse_parens() {
        let expr = parse("(proto == tcp or proto == udp) and port == 80").unwrap();
        assert!(matches!(expr, Expr::And(_, _)));
    }

    #[test]
    fn parse_operator_aliases() {
        let expr = parse("proto == tcp && port == 80").unwrap();
        assert!(matches!(expr, Expr::And(_, _)));

        let expr = parse("proto == tcp || proto == udp").unwrap();
        assert!(matches!(expr, Expr::Or(_, _)));

        let expr = parse("!proto == arp").unwrap();
        assert!(matches!(expr, Expr::Not(_)));
    }

    #[test]
    fn parse_len_comparison() {
        let expr = parse("len > 1000").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::Len,
                op: CompareOp::Gt,
                value: Value::Int(1000),
            }
        );
    }

    #[test]
    fn parse_empty_error() {
        assert!(parse("").is_err());
    }

    #[test]
    fn parse_unterminated_string() {
        assert!(parse("info contains \"hello").is_err());
    }

    #[test]
    fn parse_missing_value() {
        assert!(parse("proto ==").is_err());
    }

    #[test]
    fn parse_missing_paren() {
        assert!(parse("(proto == tcp").is_err());
    }
}
