# Data Mapping & Assembly

Reference for documenting the transition between API layers and Database layers.

## DTO to Entity Strategy
- **Decoupling**: DTOs (Data Transfer Objects) prevent internal database details from leaking into the JSON API.
- **Mass Assignment**: By using DTOs, we prevent attackers from injecting fields (like `role` or `id`) that shouldn't be modifiable by the client.

## Mapping Tools
- **ModelMapper**: Used for high-volume, standard field copying.
- **Lombok @Builder**: Used for secure, manual assembly of complex entities (like RefreshTokens) where specific fields (JTI, Expiry) require strict control.
