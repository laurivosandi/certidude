create table if not exists `tag` (
    `id` integer primary key,
    `cn` varchar(255) not null,
    `key` varchar(255) not null,
    `value` varchar(255) not null
);

create table if not exists `tag_properties` (
    `id` integer primary key,
    `tag_key` varchar(255) not null,
    `tag_value` varchar(255) not null,
    `property_key` varchar(255) not null,
    `property_value` varchar(255) not null
);

/*

create table if not exists `device_tag` (
    `id` int(11) not null,
    `device_id` varchar(45) not null,
    `tag_id` varchar(45) not null,
    `attached` timestamp null default current_timestamp,
    primary key (`id`)
);

create table if not exists `device` (
    `id` int(11) not null,
    `created` timestamp not null default current_timestamp,
    `cn` varchar(255) not null,
    `product_model` varchar(50) not null,
    `product_serial` varchar(50) default null,
    `hardware_address` varchar(17) unique not null,
    primary key (`id`)
);

*/
