import { CSRFHeaderName } from "#common/api/middleware";
import { globalAK } from "#common/global";
import { getCookie } from "#common/utils";

export interface AccountSessionUser {
    pk: number;
    username: string;
    name: string;
    email: string;
    avatar: string;
}

export interface AccountSession {
    user: AccountSessionUser;
    current: boolean;
    active: boolean;
    disconnected: boolean;
    sessionUuid: string | null;
    expires: string | null;
    lastUsed: string | null;
    lastIp: string | null;
}

export interface AccountSessionLoginResponse {
    to: string;
}

interface AccountSessionAPIResponse extends Omit<
    AccountSession,
    "sessionUuid" | "lastUsed" | "lastIp"
> {
    session_uuid: string | null;
    last_used: string | null;
    last_ip: string | null;
}

async function accountSessionFetch<T>(
    path = "",
    init: RequestInit = {},
): Promise<T> {
    const response = await fetch(
        `${globalAK().api.base}api/v3/core/account_sessions/${path}`,
        {
            credentials: "same-origin",
            ...init,
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
                [CSRFHeaderName]: getCookie("authentik_csrf"),
                ...init.headers,
            },
        },
    );

    if (!response.ok) {
        throw response;
    }

    if (response.status === 204) {
        return undefined as T;
    }

    return response.json() as Promise<T>;
}

export function accountSessions(): Promise<AccountSession[]> {
    return accountSessionFetch<AccountSessionAPIResponse[]>().then((sessions) =>
        sessions.map((session) => ({
            user: session.user,
            current: session.current,
            active: session.active,
            disconnected: session.disconnected,
            expires: session.expires,
            sessionUuid: session.session_uuid,
            lastUsed: session.last_used,
            lastIp: session.last_ip,
        })),
    );
}

export function switchAccountSession(sessionUuid: string): Promise<void> {
    return accountSessionFetch<void>("switch/", {
        method: "POST",
        body: JSON.stringify({ session_uuid: sessionUuid }),
    });
}

export function loginWithAnotherAccount(
    next: string,
): Promise<AccountSessionLoginResponse> {
    return accountSessionFetch<AccountSessionLoginResponse>("login/", {
        method: "POST",
        body: JSON.stringify({ next }),
    });
}
