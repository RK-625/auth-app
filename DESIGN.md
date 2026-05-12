---
name: "Stitch Developer Identity System"
description: "A sleek, dark-mode-first developer tool aesthetic tailored for a high-security authentication dashboard."

colors:
  background: "#0E0E11"          # Deep dark background
  surface: "#18181B"             # Card and container background
  surface-hover: "#27272A"       # Hover state for interactive surfaces
  border-subtle: "rgba(255, 255, 255, 0.12)" # Thin, glass-like borders
  border-focus: "rgba(255, 255, 255, 0.3)"
  
  text-primary: "#F9FAFB"        # Crisp off-white for main text
  text-secondary: "#9CA3AF"      # Muted gray for descriptions/labels
  text-disabled: "#52525B"
  
  primary: "#FFFFFF"             # High-contrast primary actions (e.g., white buttons on dark)
  on-primary: "#000000"          # Text on primary buttons
  
  error: "#EF4444"               # Red for validation/OTP failures
  error-surface: "rgba(239, 68, 68, 0.1)"
  success: "#10B981"             # Green for successful verifications

typography:
  font-family: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
  display:
    size: "3.5rem"
    weight: "700"
    letter-spacing: "-0.02em"
    line-height: "1.1"
  h1:
    size: "2.25rem"
    weight: "600"
    letter-spacing: "-0.01em"
  h2:
    size: "1.5rem"
    weight: "500"
  body-lg:
    size: "1.125rem"
    weight: "400"
    line-height: "1.6"
  body-md:
    size: "1rem"
    weight: "400"
    line-height: "1.5"
  body-sm:
    size: "0.875rem"
    weight: "400"
  label:
    size: "0.875rem"
    weight: "500"
    letter-spacing: "0.01em"

spacing:
  xs: "0.25rem"   # 4px
  sm: "0.5rem"    # 8px
  md: "1rem"      # 16px
  lg: "1.5rem"    # 24px
  xl: "2rem"      # 32px
  2xl: "3rem"     # 48px
  3xl: "4rem"     # 64px

radii:
  sm: "0.375rem"  # 6px
  md: "0.5rem"    # 8px
  lg: "0.75rem"   # 12px
  xl: "1rem"      # 16px
  full: "9999px"  # Pill-shaped

shadows:
  card: "0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -1px rgba(0, 0, 0, 0.3)"
  glow: "0 0 15px rgba(255, 255, 255, 0.05)"

components:
  card:
    background: "{colors.surface}"
    border: "1px solid {colors.border-subtle}"
    border-radius: "{radii.xl}"
    padding: "{spacing.xl}"
    box-shadow: "{shadows.card}"
  
  button-primary:
    background: "{colors.primary}"
    color: "{colors.on-primary}"
    border-radius: "{radii.full}"
    padding: "{spacing.sm} {spacing.lg}"
    font-weight: "{typography.label.weight}"
    transition: "all 0.2s ease"
    
  button-secondary:
    background: "transparent"
    color: "{colors.text-primary}"
    border: "1px solid {colors.border-subtle}"
    border-radius: "{radii.full}"
    padding: "{spacing.sm} {spacing.lg}"
    
  input-field:
    background: "rgba(255, 255, 255, 0.03)"
    border: "1px solid {colors.border-subtle}"
    border-radius: "{radii.md}"
    color: "{colors.text-primary}"
    padding: "{spacing.md}"
    font-size: "{typography.body-md.size}"
    transition: "border-color 0.2s ease"
---

# 🎨 Developer Identity System: UX Blueprint

This document specifies the visual identity and interaction logic for the Auth-App frontend. It is designed to perfectly synchronize with the **Spring Boot 3.4 Hybrid Security Backend**.

## 🔮 Brand & Aesthetic
The visual identity is built for developers. It employs a high-contrast dark mode aesthetic inspired by terminal environments and modern coding agents.

**Key Visual Signatures:**
*   **The Dot Grid:** The main application background should feature a subtle, low-opacity dot grid pattern (e.g., 1px dots spaced every 24px, opacity 10%).
*   **Glassy Depth:** Borders use thin, semi-transparent `{colors.border-subtle}` to create depth without relying on heavy shadows.
*   **Pill Shapes:** Interactive elements (buttons, chips) use `{radii.full}` for a soft contrast against sharp layout structures.
*   **Semantic Colors:** Color is reserved for feedback—**Emerald** for success, **Rose** for errors, and **White** for primary intent.

---

## 🔒 Backend API Contract & UI Implementation

### 1. Hybrid Session Strategy (Stateful Stateless)
The backend uses a dual-token system. The frontend must implement this specific handling:
*   **Access Token (Stateless JWT):** Received in the JSON response body. Store in memory (not localStorage) and attach as `Authorization: Bearer <token>` to all API calls.
*   **Refresh Token (Stateful Persistence):** Automatically managed by the browser via an `HttpOnly`, `Secure` cookie. **Do not attempt to access this via JavaScript.**
*   **Auto-Refresh Interceptor:** Catch `401 Unauthorized` errors. Trigger a silent `POST /api/v1/auth/refresh` (body can be empty if using cookies). If successful, retry the failed request with the new access token.

### 2. The 3-Phase Signup Handshake
To prevent bot-spam and unverified entries, the Signup process is a strict state machine:

1.  **Phase 1: Initiation**
    *   **UI:** Collect `email`.
    *   **Endpoint:** `POST /api/v1/auth/signup/request`.
    *   **Success:** Transition to OTP entry.
2.  **Phase 2: Proof-of-Possession**
    *   **UI:** 6-digit OTP input. Include a "Resend" button with a **60-second visual cooldown**.
    *   **Endpoint:** `POST /api/v1/auth/signup/verifyotp`.
    *   **Payload:** `{ "email": "...", "otp": "..." }`.
    *   **Response:** Captures the `{ "token": "signUpToken-uuid" }` for the final step.
3.  **Phase 3: Provisioning**
    *   **UI:** Password creation (min 6 chars).
    *   **Endpoint:** `POST /api/v1/auth/signup/verifytoken`.
    *   **Payload:** `{ "email", "otp", "signUpToken", "password" }`.
    *   **Success:** Redirect to Login.

### 3. Account Recovery (Forget Password)
Exactly mirrors the 3-Phase Signup handshake.
*   **Endpoint 1:** `POST /api/v1/auth/forget/email`.
*   **Endpoint 2:** `POST /api/v1/auth/forget/otp` -> Returns `resetToken`.
*   **Endpoint 3:** `POST /api/v1/auth/forget/reset`.

### 4. Rate Limiting & Error Feedback
The backend implements **Token Bucket** throttling. 
*   **Handling 429:** On a `429 Too Many Requests` status, the UI must display the localized `message` from the `ApiError` body and temporarily disable the action button.
*   **Global Error Shape:** All errors follow the `ApiError` DTO: `{ status, error, message, path, timestamp }`. Always map the `message` field to your toast notifications.

### 5. Social Login (GitHub/Google)
*   **Interaction:** Redirect the main browser window to `/oauth2/authorization/github` or `/google`.
*   **Handshake:** The backend performs JIT (Just-In-Time) provisioning and then redirects the browser back to `http://localhost:3000/oauth2/redirect/`.
*   **Sync:** The frontend should then trigger a session-check to fetch the user profile and access token.

---
*Generated with 💎 Gemini CLI & Javadoc-Pro Skill*
