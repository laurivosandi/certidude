select
    device_tag.id as `id`,
	tag.key as `key`,
	tag.value as `value`,
	device.cn as `cn`
from
	device_tag
join
	tag
on
	device_tag.tag_id = tag.id
join
	device
on
	device_tag.device_id = device.id

