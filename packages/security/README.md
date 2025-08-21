# @agenda-bella/security

Package de segurança do monorepo Agenda Bella, fornecendo fundação modular para autenticação, autorização, rate limiting e segurança de senhas.

## Status Atual

Este package implementa a estrutura base modular e utilities fundamentais. Os módulos de alto nível (JWT, CASL, etc.) serão implementados nas próximas tasks SEC-002 a SEC-005.

### Implementado ✅

- ✅ Estrutura modular completa com TypeScript strict mode
- ✅ Sistema hierárquico de erros (`SecurityError`, `AuthenticationError`, etc.)
- ✅ Utilities criptográficos seguros (`generateSecureToken`, `hashSHA256`, etc.)
- ✅ Validações robustas (`isValidEmail`, `isValidPassword`, etc.)
- ✅ Middleware utilities para Express
- ✅ Constants e configurações de segurança
- ✅ Integração com logger do package shared
- ✅ Estrutura de testes com Jest

### Em Desenvolvimento 🚧

- 🚧 **SEC-002**: Implementação JWT Authentication
- 🚧 **SEC-003**: Sistema ACL com CASL Authorization
- 🚧 **SEC-004**: Rate Limiting implementação
- 🚧 **SEC-005**: Password Security avançada

## Instalação

```bash
pnpm add @agenda-bella/security
```

## Uso Básico

### Utilities Criptográficos

```typescript
import {
  constantTimeCompare,
  generateSecureSecret,
  generateSecureToken,
  hashSHA256,
} from '@agenda-bella/security';

// Gerar token seguro (32 bytes em hex)
const token = generateSecureToken(32);

// Gerar secret para JWT (32 bytes em base64url)
const secret = generateSecureSecret(32);

// Hash SHA-256 seguro
const hash = hashSHA256('sensitive-data');

// Comparação resistente a timing attacks
const isEqual = constantTimeCompare(hash1, hash2);
```

### Validações

```typescript
import {
  getPasswordValidationDetails,
  isValidEmail,
  isValidIPAddress,
  isValidPassword,
  sanitizeInput,
} from '@agenda-bella/security';

// Validar email (RFC 5322)
const isValidEmail = isValidEmail('usuario@example.com');

// Validar senha com política customizada
const isValidPass = isValidPassword('MinhaSenh@123', {
  minLength: 8,
  requireNumbers: true,
  requireSymbols: true,
  requireUppercase: true,
  requireLowercase: true,
});

// Obter feedback detalhado de validação
const details = getPasswordValidationDetails('senha123');
console.log(details.feedback); // ['Precisa de letras maiúsculas', 'Precisa de símbolos']

// Sanitizar input contra XSS
const clean = sanitizeInput('<script>alert("xss")</script>Hello');

// Validar IP address
const isValidIP = isValidIPAddress('192.168.1.1');
```

### Error Handling

```typescript
import {
  AuthenticationError,
  AuthorizationError,
  PasswordPolicyError,
  RateLimitError,
  SecurityError,
} from '@agenda-bella/security';

try {
  // Operação que pode gerar erro de segurança
  throw new AuthenticationError('Token inválido', { userId: '123' });
} catch (error) {
  if (error instanceof SecurityError) {
    console.log(`Erro de segurança: ${error.code} - ${error.message}`);
    console.log(`Status HTTP: ${error.statusCode}`);
    console.log(`Context:`, error.context);
  }
}
```

### Middleware para Express

```typescript
import {
  createErrorHandler,
  createSecurityContext,
  extractBearerToken,
  getClientIP,
} from '@agenda-bella/security';

// Error handler padronizado
const errorHandler = createErrorHandler();
app.use(errorHandler);

// Middleware personalizado
app.use((req, res, next) => {
  // Extrair Bearer token
  const token = extractBearerToken(req);

  // Obter IP do cliente (suporta X-Forwarded-For)
  const clientIP = getClientIP(req);

  // Criar contexto de segurança
  const securityContext = createSecurityContext(req);

  // Adicionar ao request
  req.securityContext = securityContext;
  next();
});
```

### Logging e Auditoria

```typescript
import {
  auditLog,
  logSecurityError,
  securityLogger,
  trackSecurityMetric,
} from '@agenda-bella/security';

// Logger específico de segurança
securityLogger.info('User login attempt', { userId: '123' });

// Log de auditoria
auditLog('USER_LOGIN', {
  userId: '123',
  ip: '192.168.1.1',
  success: true,
});

// Log de erro de segurança
const error = new AuthenticationError('Token expired');
logSecurityError(error, { userId: '123' });

// Métricas de segurança
trackSecurityMetric('login_attempts', 1, { success: 'true' });
```

## Módulos Disponíveis

### Core Types

- **types/**: Interfaces e tipos base (`SecurityContext`, `SecurityConfig`, etc.)
- **types/errors.types**: Hierarquia de erros de segurança

### Foundation Modules

- **auth/**: Base para autenticação JWT (implementação em SEC-002)
- **authorization/**: Base para ACL/CASL (implementação em SEC-003)
- **password/**: Base para segurança de senhas (implementação em SEC-005)
- **rate-limiter/**: Base para rate limiting (implementação em SEC-004)
- **middleware/**: Utilities para middleware Express

### Utilities & Constants

- **utils/crypto**: Funções criptográficas seguras
- **utils/validation**: Validações robustas e sanitização
- **constants/**: Constants de erros, permissões e configurações

## Development

```bash
# Instalar dependências
pnpm install

# Build do package
pnpm build

# Executar testes
pnpm test

# Type checking
pnpm type-check

# Linting
pnpm lint

# Auditoria de segurança
pnpm audit
```

## Estrutura do Package

```
packages/security/src/
├── types/              # Interfaces e tipos base
├── auth/               # Base para autenticação (SEC-002)
├── authorization/      # Base para ACL/CASL (SEC-003)
├── password/           # Base para password security (SEC-005)
├── rate-limiter/       # Base para rate limiting (SEC-004)
├── middleware/         # Utilities Express
├── constants/          # Constants do sistema
├── utils/              # Crypto e validation utilities
└── index.ts           # Exports principais
```

## Roadmap - Próximas Implementações

### SEC-002: JWT Authentication [4h]

- Implementação completa de JWT tokens
- Access e refresh token rotation
- Middleware de autenticação Express
- Integração com Redis para blacklist

### SEC-003: ACL Authorization [4h]

- Sistema completo de ACL com CASL
- Definição de roles e permissions
- Middleware de autorização Express
- Context-aware permissions

### SEC-004: Rate Limiting [3h]

- Rate limiting distribuído com Redis
- Múltiplas estratégias (sliding window, fixed window, token bucket)
- Rate limiting por IP, usuário e endpoint
- Middleware Express integrado

### SEC-005: Password Security [3h]

- Hash bcrypt com salt rounds configuráveis
- Verificação de força de senha avançada
- Prevenção contra senhas comuns
- Histórico de senhas e rotação

## Contribuição

Este package segue os padrões do monorepo Agenda Bella:

- TypeScript Strict Mode obrigatório
- Testes com cobertura mínima de 75%
- Documentação JSDoc completa
- Integração com packages shared e database

## License

Proprietary - Agenda Bella Marketplace
