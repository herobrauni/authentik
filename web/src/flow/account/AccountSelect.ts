import "#elements/EmptyState";
import "#elements/locale/ak-locale-select";
import "#flow/components/ak-flow-card";

import {
    AccountSession,
    accountSessions,
    loginWithAnotherAccount,
    switchAccountSession,
} from "#common/account-sessions";
import { globalAK } from "#common/global";
import { formatDisambiguatedUserDisplayName } from "#common/users";

import { Interface } from "#elements/Interface";
import { WithBrandConfig } from "#elements/mixins/branding";
import { ThemedImage, isDefaultAvatar } from "#elements/utils/images";

import { msg } from "@lit/localize";
import { CSSResult, css, html, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { repeat } from "lit/directives/repeat.js";

import PFAvatar from "@patternfly/patternfly/components/Avatar/avatar.css";
import PFButton from "@patternfly/patternfly/components/Button/button.css";
import PFLogin from "@patternfly/patternfly/components/Login/login.css";
import PFTitle from "@patternfly/patternfly/components/Title/title.css";

@customElement("ak-account-select")
export class AccountSelect extends WithBrandConfig(Interface) {
    static styles: CSSResult[] = [
        PFLogin,
        PFButton,
        PFTitle,
        PFAvatar,
        css`
            .account-list {
                display: flex;
                flex-direction: column;
                gap: var(--pf-global--spacer--sm);
            }

            .account-button {
                width: 100%;
                justify-content: flex-start;
                padding: var(--pf-global--spacer--md);
                text-align: start;
            }

            .account-content {
                display: flex;
                align-items: center;
                gap: var(--pf-global--spacer--md);
                width: 100%;
            }

            .account-text {
                display: flex;
                flex: 1;
                min-width: 0;
                flex-direction: column;
                line-height: 1.3;
            }

            .account-name,
            .account-meta {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }

            .account-meta {
                color: var(--pf-global--Color--200);
                font-size: var(--pf-global--FontSize--sm);
            }

            .account-status {
                margin-inline-start: auto;
                color: var(--pf-global--Color--200);
                font-size: var(--pf-global--FontSize--sm);
            }

            .actions {
                display: flex;
                flex-direction: column;
                gap: var(--pf-global--spacer--sm);
                padding-top: var(--pf-global--spacer--md);
            }
        `,
    ];

    @state()
    protected accounts: AccountSession[] = [];

    @state()
    protected loading = true;

    @state()
    protected error = false;

    protected get nextUrl(): string {
        const next = new URLSearchParams(window.location.search).get("next");
        if (!next) {
            return globalAK().api.base;
        }
        try {
            const parsed = new URL(next, window.location.origin);
            if (parsed.origin !== window.location.origin) {
                return globalAK().api.base;
            }
            return `${parsed.pathname}${parsed.search}${parsed.hash}`;
        } catch (_error) {
            return globalAK().api.base;
        }
    }

    public override connectedCallback(): void {
        super.connectedCallback();
        this.refreshAccounts();
    }

    protected async refreshAccounts(): Promise<void> {
        this.loading = true;
        this.error = false;
        try {
            this.accounts = await accountSessions();
        } catch (error) {
            console.debug(
                "authentik/account-select: failed to load accounts",
                error,
            );
            this.error = true;
        } finally {
            this.loading = false;
        }
    }

    protected selectAccount = async (
        account: AccountSession,
    ): Promise<void> => {
        if (!account.active || !account.sessionUuid) {
            return;
        }
        if (!account.current) {
            await switchAccountSession(account.sessionUuid);
        }
        window.location.assign(this.nextUrl);
    };

    protected addAccount = async (): Promise<void> => {
        const response = await loginWithAnotherAccount(this.nextUrl);
        window.location.assign(response.to);
    };

    protected renderAvatar(account: AccountSession) {
        const avatar = account.user.avatar;
        if (!avatar || isDefaultAvatar(avatar)) {
            return html`<i
                class="fas fa-user-circle fa-2x"
                aria-hidden="true"
            ></i>`;
        }
        return html`<img
            class="pf-c-avatar"
            src=${avatar}
            alt=${msg("Avatar image")}
        />`;
    }

    protected renderAccount(account: AccountSession) {
        const label = formatDisambiguatedUserDisplayName(account.user);
        return html`<button
            class="pf-c-button pf-m-secondary account-button"
            type="button"
            ?disabled=${!account.active}
            @click=${() => this.selectAccount(account)}
        >
            <span class="account-content">
                ${this.renderAvatar(account)}
                <span class="account-text">
                    <strong class="account-name">${label}</strong>
                    ${account.user.email
                        ? html`<span class="account-meta"
                              >${account.user.email}</span
                          >`
                        : nothing}
                </span>
                <span class="account-status">
                    ${account.current
                        ? msg("Current")
                        : account.disconnected
                          ? msg("Disconnected")
                          : nothing}
                </span>
            </span>
        </button>`;
    }

    protected renderBody() {
        if (this.loading) {
            return html`<ak-empty-state
                loading
                default-label
            ></ak-empty-state>`;
        }
        if (this.error) {
            return html`<ak-empty-state
                icon="pf-icon-error-circle-o"
                header=${msg("Failed to load accounts")}
            ></ak-empty-state>`;
        }
        return html`<p>${msg("Choose the account to continue with.")}</p>
            <div class="account-list">
                ${repeat(
                    this.accounts,
                    (account) => account.user.pk,
                    (account) => this.renderAccount(account),
                )}
            </div>
            <div class="actions">
                <button
                    class="pf-c-button pf-m-link pf-m-block"
                    type="button"
                    @click=${this.addAccount}
                >
                    <i
                        class="fas fa-plus pf-c-button__icon pf-m-start"
                        aria-hidden="true"
                    ></i>
                    ${msg("Use another account")}
                </button>
            </div>`;
    }

    protected override render() {
        return html`<ak-locale-select class="pf-m-dark"></ak-locale-select>
            <main
                class="pf-c-login__main"
                aria-label=${msg("Account selection")}
            >
                <div class="pf-c-login__main-header pf-c-brand">
                    ${ThemedImage({
                        src: this.brandingLogo,
                        alt: msg("authentik Logo"),
                        className: "branding-logo",
                        theme: this.activeTheme,
                        themedUrls: this.brandingLogoThemedUrls,
                    })}
                </div>
                <ak-flow-card .challenge=${{ flowInfo: {} }}>
                    <span slot="title">${msg("Choose an account")}</span>
                    ${this.renderBody()}
                </ak-flow-card>
            </main>
            <footer
                class="pf-c-login__footer pf-m-dark"
                aria-label=${msg("Site footer")}
            >
                <slot name="footer"></slot>
            </footer>`;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-account-select": AccountSelect;
    }
}
