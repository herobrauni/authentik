import "#elements/forms/HorizontalFormElement";
import "#components/ak-switch-input";
import "#elements/buttons/ActionButton/ak-action-button";
import "#elements/buttons/Dropdown";
import "@patternfly/elements/pf-tooltip/pf-tooltip.js";

import {
    AccountSession,
    accountSessions,
    loginWithAnotherAccount,
    switchAccountSession,
} from "#common/account-sessions";
import { DEFAULT_CONFIG } from "#common/api/config";
import { globalAK } from "#common/global";
import { formatUserDisplayName } from "#common/users";

import { AKElement } from "#elements/Base";
import { WithNotifications } from "#elements/mixins/notifications";
import { WithSession } from "#elements/mixins/session";
import { AKDrawerChangeEvent } from "#elements/notifications/events";
import { isDefaultAvatar } from "#elements/utils/images";

import Styles from "#components/ak-nav-button.css";

import { CoreApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { guard } from "lit/directives/guard.js";

import PFAvatar from "@patternfly/patternfly/components/Avatar/avatar.css";
import PFBrand from "@patternfly/patternfly/components/Brand/brand.css";
import PFButton from "@patternfly/patternfly/components/Button/button.css";
import PFDrawer from "@patternfly/patternfly/components/Drawer/drawer.css";
import PFDropdown from "@patternfly/patternfly/components/Dropdown/dropdown.css";
import PFNotificationBadge from "@patternfly/patternfly/components/NotificationBadge/notification-badge.css";
import PFPage from "@patternfly/patternfly/components/Page/page.css";
import PFDisplay from "@patternfly/patternfly/utilities/Display/display.css";

@customElement("ak-nav-buttons")
export class NavigationButtons extends WithNotifications(
    WithSession(AKElement),
) {
    @property({ type: Boolean, reflect: true })
    notificationDrawerOpen = false;

    @property({ type: Boolean, reflect: true })
    apiDrawerOpen = false;

    @state()
    protected accountSessions: AccountSession[] = [];

    static styles = [
        PFDisplay,
        PFBrand,
        PFPage,
        PFAvatar,
        PFButton,
        PFDrawer,
        PFDropdown,
        PFNotificationBadge,
        Styles,
    ];

    public override connectedCallback(): void {
        super.connectedCallback();
        this.refreshAccountSessions();
    }

    protected async refreshAccountSessions(): Promise<void> {
        try {
            this.accountSessions = await accountSessions();
        } catch (error) {
            console.debug(
                "authentik/nav: failed to load account sessions",
                error,
            );
        }
    }

    protected switchAccount = async (
        account: AccountSession,
    ): Promise<void> => {
        if (!account.active || !account.sessionUuid || account.current) {
            return;
        }
        await switchAccountSession(account.sessionUuid);
        window.location.reload();
    };

    protected addAccount = async (): Promise<void> => {
        const { pathname, search, hash } = window.location;
        const response = await loginWithAnotherAccount(`${pathname}${search}${hash}`);
        window.location.assign(response.to);
    };

    protected renderAPIDrawerTrigger() {
        const { apiDrawer } = this.uiConfig.enabledFeatures;

        return guard([apiDrawer], () => {
            if (!apiDrawer) {
                return nothing;
            }

            return html`<div
                class="pf-c-page__header-tools-item pf-m-hidden pf-m-visible-on-xl"
            >
                <button
                    id="api-drawer-toggle-button"
                    class="pf-c-button pf-m-plain"
                    type="button"
                    aria-label=${msg("Toggle API requests drawer", {
                        id: "drawer-toggle-button-api-requests",
                    })}
                    @click=${AKDrawerChangeEvent.dispatchAPIToggle}
                >
                    <pf-tooltip
                        position="top"
                        content=${msg("API Drawer")}
                        trigger="api-drawer-toggle-button"
                    >
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            class="ak-c-vector-icon"
                            fill="currentColor"
                            aria-hidden="true"
                            viewBox="0 0 32 32"
                        >
                            <path
                                d="M8 9H4a2 2 0 0 0-2 2v12h2v-5h4v5h2V11a2 2 0 0 0-2-2m-4 7v-5h4v5ZM22 11h3v10h-3v2h8v-2h-3V11h3V9h-8zM14 23h-2V9h6a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-4Zm0-7h4v-5h-4Z"
                            />
                        </svg>
                    </pf-tooltip>
                </button>
            </div>`;
        });
    }

    protected renderNotificationDrawerTrigger() {
        const { notificationDrawer } = this.uiConfig.enabledFeatures;
        const notificationCount = this.notificationCount;

        return guard([notificationDrawer, notificationCount], () => {
            if (!notificationDrawer) {
                return nothing;
            }

            return html`<div
                class="pf-c-page__header-tools-item pf-m-hidden pf-m-visible-on-xl"
            >
                <button
                    id="notification-drawer-toggle-button"
                    class="pf-c-button pf-m-plain"
                    type="button"
                    aria-label=${msg("Toggle notifications drawer", {
                        id: "drawer-toggle-button-notifications",
                    })}
                    aria-describedby="notification-count"
                    @click=${AKDrawerChangeEvent.dispatchNotificationsToggle}
                >
                    <span
                        class="pf-c-notification-badge ${notificationCount
                            ? "pf-m-unread"
                            : ""}"
                    >
                        <pf-tooltip
                            position="top"
                            content=${msg("Notification Drawer", {
                                id: "drawer-invoker-tooltip-notifications",
                            })}
                            trigger="notification-drawer-toggle-button"
                        >
                            <i class="fas fa-bell" aria-hidden="true"></i>
                        </pf-tooltip>
                        <span
                            id="notification-count"
                            class="pf-c-notification-badge__count"
                            aria-live="polite"
                        >
                            ${notificationCount}
                            <span class="sr-only">unread</span>
                        </span>
                    </span>
                </button>
            </div>`;
        });
    }

    renderImpersonation() {
        if (!this.impersonating) return nothing;

        const onClick = async () => {
            await new CoreApi(DEFAULT_CONFIG).coreUsersImpersonateEndRetrieve();
            window.location.reload();
        };

        return html`&nbsp;
            <div class="pf-c-page__header-tools">
                <div class="pf-c-page__header-tools-group">
                    <ak-action-button
                        class="pf-m-warning pf-m-small"
                        .apiRequest=${onClick}
                    >
                        ${msg("Stop impersonation")}
                    </ak-action-button>
                </div>
            </div>`;
    }

    protected renderAccountAvatar(avatar?: string) {
        if (!avatar || isDefaultAvatar(avatar)) {
            return html`<span class="account-switcher-icon" aria-hidden="true">
                <i class="fas fa-user-circle"></i>
            </span>`;
        }
        return html`<img
            class="pf-c-avatar account-switcher-avatar"
            src=${avatar}
            alt=""
        />`;
    }

    protected renderAccountMenuItem(account: AccountSession) {
        const label =
            formatUserDisplayName(account.user, this.uiConfig) ||
            account.user.username;
        return html`<li role="presentation">
            <button
                class="pf-c-dropdown__menu-item account-switcher-item"
                type="button"
                role="menuitem"
                ?disabled=${!account.active || account.current}
                @click=${() => this.switchAccount(account)}
            >
                ${this.renderAccountAvatar(account.user.avatar)}
                <span class="account-switcher-text">
                    <span class="account-switcher-name">${label}</span>
                    ${account.user.email
                        ? html`<small class="account-switcher-meta"
                              >${account.user.email}</small
                          >`
                        : nothing}
                </span>
                ${account.current
                    ? html`<small class="account-switcher-status"
                          >${msg("Current")}</small
                      >`
                    : account.disconnected
                      ? html`<small class="account-switcher-status"
                            >${msg("Disconnected")}</small
                        >`
                      : nothing}
            </button>
        </li>`;
    }

    protected renderUserMenu(displayName: string) {
        const { currentUser } = this;
        if (!currentUser) {
            return nothing;
        }
        const label = displayName || currentUser.username;
        return html`<div class="pf-c-page__header-tools-group">
            <div class="pf-c-page__header-tools-item">
                <ak-dropdown class="pf-c-dropdown account-switcher">
                    <button
                        class="pf-c-dropdown__toggle pf-m-plain account-switcher-toggle"
                        type="button"
                        aria-label=${msg("Account menu")}
                    >
                        ${this.renderAccountAvatar(currentUser.avatar)}
                        <span
                            class="account-switcher-label pf-m-hidden pf-m-visible-on-2xl"
                            >${label}</span
                        >
                        <i
                            class="fas fa-caret-down pf-c-dropdown__toggle-icon"
                            aria-hidden="true"
                        ></i>
                    </button>
                    <menu class="pf-c-dropdown__menu pf-m-align-right">
                        ${this.accountSessions.map((account) =>
                            this.renderAccountMenuItem(account),
                        )}
                        ${this.accountSessions.length
                            ? html`<hr class="pf-c-divider" />`
                            : nothing}
                        <li role="presentation">
                            <button
                                class="pf-c-dropdown__menu-item"
                                type="button"
                                role="menuitem"
                                @click=${this.addAccount}
                            >
                                <i class="fas fa-plus" aria-hidden="true"></i
                                >&nbsp;${msg("Use another account")}
                            </button>
                        </li>
                        ${this.uiConfig?.enabledFeatures.settings
                            ? html`<li role="presentation">
                                  <a
                                      class="pf-c-dropdown__menu-item"
                                      role="menuitem"
                                      href="${globalAK().api
                                          .base}if/user/#/settings"
                                  >
                                      <i
                                          class="fas fa-cog"
                                          aria-hidden="true"
                                      ></i
                                      >&nbsp;${msg("Settings")}
                                  </a>
                              </li>`
                            : nothing}
                        <li role="presentation">
                            <a
                                class="pf-c-dropdown__menu-item"
                                role="menuitem"
                                href="${globalAK().api
                                    .base}flows/-/default/invalidation/"
                            >
                                <i
                                    class="fas fa-sign-out-alt"
                                    aria-hidden="true"
                                ></i
                                >&nbsp;${msg("Sign out")}
                            </a>
                        </li>
                    </menu>
                </ak-dropdown>
            </div>
        </div>`;
    }

    render() {
        const displayName = formatUserDisplayName(
            this.currentUser,
            this.uiConfig,
        );

        return html`<div role="presentation" class="pf-c-page__header-tools">
            <div class="pf-c-page__header-tools-group">
                ${this.renderAPIDrawerTrigger()}
                <!-- -->
                ${this.renderNotificationDrawerTrigger()}
                <!-- -->
                <slot name="extra"></slot>
            </div>
            ${this.renderImpersonation()} ${this.renderUserMenu(displayName)}
            <slot></slot>
        </div>`;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-nav-buttons": NavigationButtons;
    }
}
