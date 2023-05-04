<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2018, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Joas Schilling <coding@schilljs.com>
 * @author Julius Härtl <jus@bitgrid.net>
 * @author Roeland Jago Douma <roeland@famdouma.nl>
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
namespace OCA\DAV\CardDAV;

use OCA\Federation\TrustedServers;
use OCP\Accounts\IAccountManager;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IRequest;
use Sabre\CardDAV\Backend\BackendInterface;
use Sabre\CardDAV\Card;
use Sabre\DAV\Exception\NotFound;
use Sabre\VObject\Component\VCard;
use Sabre\VObject\Reader;

class SystemAddressbook extends AddressBook {
	/** @var IConfig */
	private $config;
	private ?TrustedServers $trustedServers;
	private ?IRequest $request;

	public function __construct(BackendInterface $carddavBackend, array $addressBookInfo, IL10N $l10n, IConfig $config, ?IRequest $request = null, ?TrustedServers $trustedServers = null) {
		parent::__construct($carddavBackend, $addressBookInfo, $l10n);
		$this->config = $config;
		$this->request = $request;
		$this->trustedServers = $trustedServers;
	}

	public function getChildren() {
		$shareEnumeration = $this->config->getAppValue('core', 'shareapi_allow_share_dialog_user_enumeration', 'yes') === 'yes';
		$shareEnumerationGroup = $this->config->getAppValue('core', 'shareapi_restrict_user_enumeration_to_group', 'no') === 'yes';
		$shareEnumerationPhone = $this->config->getAppValue('core', 'shareapi_restrict_user_enumeration_to_phone', 'no') === 'yes';
		if (!$shareEnumeration || $shareEnumerationGroup || $shareEnumerationPhone) {
			return [];
		}

		return parent::getChildren();
	}

	/**
	 * @param string $name
	 * @return Card
	 * @throws NotFound
	 */
	public function getChild($name): Card {
		if ($this->trustedServers === null || $this->request === null) {
			return parent::getChild($name);
		}

		/* @psalm-suppress NoInterfaceProperties */
		if ($this->request->server['PHP_AUTH_USER'] !== 'system') {
			return parent::getChild($name);
		}

		/* @psalm-suppress NoInterfaceProperties */
		$sharedSecret = $this->request->server['PHP_AUTH_PW'];
		if ($sharedSecret === null) {
			return parent::getChild($name);
		}

		$servers = $this->trustedServers->getServers();
		$trusted = array_filter($servers, function ($trustedServer) use ($sharedSecret) {
			return $trustedServer['shared_secret'] === $sharedSecret;
		});
		// Authentication is fine, but it's not for a federated share
		if (empty($trusted)) {
			return parent::getChild($name);
		}

		$obj = $this->carddavBackend->getCard($this->addressBookInfo['id'], $name);
		if (!$obj) {
			throw new NotFound('Card not found');
		}
		$obj['acl'] = $this->getChildACL();
		$cardData = $obj['carddata'];
		/** @var VCard $vCard */
		$vCard = Reader::read($cardData);
		foreach ($vCard->children() as $child) {
			$scope = $child->offsetGet('X-NC-SCOPE');
			if ($scope !== null && $scope->getValue() === IAccountManager::SCOPE_LOCAL) {
				$vCard->remove($child);
			}
		}
		$messages = $vCard->validate();
		if (!empty($messages)) {
			// If the validation doesn't work the card is indeed "not found"
			// even if it might exist in the local backend.
			// This can happen when a user sets the required properties
			// FN, N to a local scope only.
			// @see https://github.com/nextcloud/server/issues/38042
			throw new NotFound('Card not found');
		}
		$obj['carddata'] = $vCard->serialize();
		return new Card($this->carddavBackend, $this->addressBookInfo, $obj);
	}
}
