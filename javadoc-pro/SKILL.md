---
name: javadoc-pro
description: Generates professional, deep-dive Javadoc for Spring Boot applications. Use when you need to explain complex workflows, behind-the-scenes bean interactions, and architectural "why" decisions for junior developers.
---

# Javadoc Pro

This skill transforms basic code comments into high-signal technical specifications for Spring Boot applications. It focuses on the "How" and "Why" rather than just the "What."

## Core Objective: Self-Explaining Architecture

The goal of this skill is to turn the codebase into a **Living Textbook**. Documentation should be so thorough that a new developer can understand the entire system architecture, security handshake, and persistence logic without needing an external manual.

## Core Principles

1. **Map Component Interactions**: Do not document methods in isolation. Explain how the component interacts with others and how they work together (e.g., `Controller` -> `AuthenticationManager` -> `DaoAuthenticationProvider` -> `UserDetailsService`).
2. **Expose the Magic**: Identify the Spring Beans (e.g., {@code BCryptPasswordEncoder}, {@code SecurityContextPersistenceFilter}) working in the background.
3. **Explain the Working Logic**: Describe exactly *how* the components work together (e.g., how a raw password from a DTO is compared against a database hash).
4. **Architectural Rationale**: Explain why a pattern was chosen and what security risks it mitigates.
5. **Self-Explaining Context**: Use Javadoc to explain architectural "Why" decisions (e.g., why we chose a Hybrid Session model over pure Stateless JWT).

## Advanced Project Patterns

When documenting this specific architecture, prioritize these patterns:

1. **The Helper Bridge**: Document "Helper" classes as the formal assembly line between Services and Entities. Explain how they preserve the Single Responsibility Principle.
2. **Hybrid Session Security**: Explicitly document the "Stateful Stateless" nature of the Refresh Token. Explain that while the Access JWT is stateless, the database-backed Refresh Token provides a "Kill Switch" for the session.
3. **JIT (Just-In-Time) Provisioning**: In OAuth2 flows, document how external attributes are synchronized with the local database in real-time.

## Detailed Javadoc Pattern (Elite Uniformity)

Every core class MUST use this exact visual structure to ensure professional-grade readability:

```java
/**
 * <h1>[Component Technical Title]</h1>
 * 
 * <p>[One paragraph explaining the High-Level Purpose.]</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. [Step 1: Input/Normalization]
 * 2. [Step 2: Core Logic/Delegation]
 * 3. [Step 3: Side Effects/Persistence]
 * </p>
 * 
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * Describe exactly how the beans work together. Use {@code code} tags for beans 
 * and {@link} for related classes.
 * </p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * [Why this specific architectural pattern? E.g., mitigates XSS, ensures 
 * thread-safety, or enables a Hybrid Session Kill-Switch.]
 * </p>
 */
```

## High-Signal Formatting Rules

To make the documentation "Self-Explaining" at a glance:
1.  **Use {@code BeanName}**: For Spring beans that are not directly imported in the file.
2.  **Use {@link ClassName}**: For classes that exist within the project context.
3.  **Bold the "Actions"**: Use `<b>` for key implementation steps (e.g., <b>Normalization</b>, <b>Provisioning</b>).
4.  **Document the Constraint**: When documenting fields, explain the *Constraint* (e.g., `updatable = false`) and its security purpose.

## Exception Documentation Pattern

For Global Exception Handlers or custom exceptions, use this pattern to explain the error lifecycle:

```java
/**
 * [Error Category: e.g., Authentication Failure]
 *
 * <p><b>Triggering Conditions:</b>
 * Occurs when [specific state, e.g., JWT signature is invalid or expired].
 * </p>
 *
 * <p><b>Developer Note:</b>
 * This exception is caught by the {@code GlobalExceptionHandler} and mapped to a 
 * {@link com.substring.authapp.dtos.common.ApiError} DTO.
 It ensures that internal stack 
 * traces are suppressed to prevent information leakage in production.
 * </p>
 *
 * @see [RelatedService] For the logic that throws this error.
 */
```

## Flexibility & Contextual Adaptation

**The "Clarity Over Consistency" Rule:** While the above templates are the standard, you MUST deviate from them if:
1. A method is extremely simple (don't over-engineer docs for a getter).
2. A complex algorithm requires a **Mathematical Proof** or **State Machine Diagram** instead of a numbered list.
3. The logic involves **Third-Party Integrations** (like OAuth2) where explaining the external API's behavior is more important than the internal bean logic.

In these cases, prioritize whatever structure makes the code most "self-teaching" for a new developer.

## References

For deep dives into specific Spring modules, see:
- [SPRING_SECURITY.md](references/SPRING_SECURITY.md): Deep dive into Filter Chains, AuthenticationProviders, and JWT mechanics.
- [PERSISTENCE.md](references/PERSISTENCE.md): Details on JPA lifecycle, Transactional boundaries, and Index optimization.
- [OAUTH2_JIT.md](references/OAUTH2_JIT.md): Explains Social Login and JIT user provisioning logic.
- [MAPPING_STRATEGY.md](references/MAPPING_STRATEGY.md): Details on DTO decoupling and assembly patterns.
