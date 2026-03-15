package com.substring.authapp.dtos;

import com.substring.authapp.entities.Role;
import lombok.*;

import java.io.Serializable;
import java.util.UUID;

/**
 * DTO for {@link Role}
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class RoleDto implements Serializable {
    private UUID id;
    private String name;
}