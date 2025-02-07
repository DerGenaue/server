<!--
  - @copyright Copyright (c) 2019 Julius Härtl <jus@bitgrid.net>
  -
  - @author Julius Härtl <jus@bitgrid.net>
  -
  - @license GNU AGPL version 3 or any later version
  -
  - This program is free software: you can redistribute it and/or modify
  - it under the terms of the GNU Affero General Public License as
  - published by the Free Software Foundation, either version 3 of the
  - License, or (at your option) any later version.
  -
  - This program is distributed in the hope that it will be useful,
  - but WITHOUT ANY WARRANTY; without even the implied warranty of
  - MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  - GNU Affero General Public License for more details.
  -
  - You should have received a copy of the GNU Affero General Public License
  - along with this program. If not, see <http://www.gnu.org/licenses/>.
  -
  -->

<template>
	<div>
		<NcMultiselect :value="currentValue"
			:loading="status.isLoading && groups.length === 0"
			:options="groups"
			:multiple="false"
			label="displayname"
			track-by="id"
			@search-change="searchAsync"
			@input="(value) => $emit('input', value.id)" />
	</div>
</template>

<script>
import NcMultiselect from '@nextcloud/vue/dist/Components/NcMultiselect.js'
import axios from '@nextcloud/axios'
import { generateOcsUrl } from '@nextcloud/router'

const groups = []
const status = {
	isLoading: false,
}

export default {
	name: 'RequestUserGroup',
	components: {
		NcMultiselect,
	},
	props: {
		value: {
			type: String,
			default: '',
		},
		check: {
			type: Object,
			default: () => { return {} },
		},
	},
	data() {
		return {
			groups,
			status,
		}
	},
	computed: {
		currentValue() {
			return this.groups.find(group => group.id === this.value) || null
		},
	},
	async mounted() {
		if (this.groups.length === 0) {
			await this.searchAsync('')
		}
		if (this.currentValue === null) {
			await this.searchAsync(this.value)
		}
	},
	methods: {
		searchAsync(searchQuery) {
			if (this.status.isLoading) {
				return
			}

			this.status.isLoading = true
			return axios.get(generateOcsUrl('cloud/groups/details?limit=20&search={searchQuery}', { searchQuery })).then((response) => {
				response.data.ocs.data.groups.forEach((group) => {
					this.addGroup({
						id: group.id,
						displayname: group.displayname,
					})
				})
				this.status.isLoading = false
			}, (error) => {
				console.error('Error while loading group list', error.response)
			})
		},
		addGroup(group) {
			const index = this.groups.findIndex((item) => item.id === group.id)
			if (index === -1) {
				this.groups.push(group)
			}
		},
	},
}
</script>
<style scoped>
	.multiselect {
		width: 100%;
	}
</style>
