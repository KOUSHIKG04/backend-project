export const UserRoleEnum = {
    ADMIN: "admin",
    PROJECT_ADMIN: "project_admin",
    MEMBERS: "members"
} as const

export const AvailableUserRole = Object.values(UserRoleEnum)

export const TaskStatusEnum = {
    TODO: "todo",
    IN_PROGRESS: "in_progress",
    DONE: "done"
} as const

export const AvailableTaskStatus = Object.values(TaskStatusEnum)
