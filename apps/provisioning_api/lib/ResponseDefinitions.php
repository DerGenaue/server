<?php
declare(strict_types=1);

/**
 * @copyright Copyright (c) 2023 Kate Döen <kate.doeen@nextcloud.com>
 *
 * @author Kate Döen <kate.doeen@nextcloud.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\Provisioning_API;

/**
 * @psalm-type ProvisioningApiUserDetails = array{
 *     additional_mail: string[],
 *     additional_mailScope: string[]|null,
 *     address: string,
 *     addressScope: string|null,
 *     avatarScope: string|null,
 *     backend: string,
 *     backendCapabilities: array{
 *         setDisplayName: bool,
 *         setPassword: bool
 *     },
 *     biography: string,
 *     biographyScope: string|null,
 *     displayname: string,
 *     display-name: string,
 *     displaynameScope: string|null,
 *     email: string|null,
 *     emailScope: string|null,
 *     enabled: bool|null,
 *     fediverse: string|null,
 *     fediverseScope: string|null,
 *     groups: string[],
 *     headline: string,
 *     headlineScope: string|null,
 *     id: string,
 *     language: string,
 *     lastLogin: int,
 *     locale: string,
 *     notify_email: string|null,
 *     organisation: string,
 *     organisationScope: string|null,
 *     phone: string,
 *     phoneScope: string|null,
 *     profile_enabled: string,
 *     profile_enabledScope: string|null,
 *     quota: array{
 *         free: int|null,
 *         quota: string|int|bool,
 *         relative: float|null,
 *         total: int|null,
 *         used: int,
 *       },
 *     role: string,
 *     roleScope: string|null,
 *     storageLocation: string|null,
 *     subadmin: string[],
 *     twitter: string,
 *     twitterScope: string|null,
 *     website: string,
 *     websiteScope: string|null,
 * }
 *
 * @psalm-type ProvisioningApiAppInfo = array{
 *     active: bool|null,
 *     activity: ?mixed,
 *     author: ?mixed,
 *     background-jobs: ?mixed,
 *     bugs: ?mixed,
 *     category: ?mixed,
 *     collaboration: ?mixed,
 *     commands: ?mixed,
 *     default_enable: ?mixed,
 *     dependencies: ?mixed,
 *     description: string,
 *     discussion: ?mixed,
 *     documentation: ?mixed,
 *     groups: ?mixed,
 *     id: string,
 *     info: ?mixed,
 *     internal: bool|null,
 *     level: int|null,
 *     licence: ?mixed,
 *     name: string,
 *     namespace: ?mixed,
 *     navigations: ?mixed,
 *     preview: ?mixed,
 *     previewAsIcon: bool|null,
 *     public: ?mixed,
 *     remote: ?mixed,
 *     removable: bool|null,
 *     repair-steps: ?mixed,
 *     repository: ?mixed,
 *     sabre: ?mixed,
 *     screenshot: ?mixed,
 *     settings: ?mixed,
 *     summary: string,
 *     trash: ?mixed,
 *     two-factor-providers: ?mixed,
 *     types: ?mixed,
 *     version: string,
 *     versions: ?mixed,
 *     website: ?mixed,
 * }
 *
 * @psalm-type ProvisioningApiGroupDetails = array{
 *     id: string,
 *     displayname: string,
 *     usercount: bool|int,
 *     disabled: bool|int,
 *     canAdd: bool,
 *     canRemove: bool,
 * }
 */
class ResponseDefinitions {
}
