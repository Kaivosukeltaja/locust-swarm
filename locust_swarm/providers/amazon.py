#!/usr/bin/env python
# -*- coding: utf-8 -*-

from boto.ec2 import connect_to_region
from ..config import DEFAULT_MASTER_ROLE_NAME
from ..config import DEFAULT_SLAVE_ROLE_NAME
from ..config import DEFAULT_CUSTOM_TAG_NAME

from time import sleep

import socket



def get_master_reservations(config):
    return _get_instances_by_role(config, DEFAULT_MASTER_ROLE_NAME)


def get_master_ip_address(config):
    reservations = get_master_reservations(config)
    if reservations:
        for reservation in reservations:
            for instance in reservation.instances:
                if instance.ip_address and instance.state == 'running':
                    return instance.private_ip_address
    return None


def get_slave_reservations(config):
    return _get_instances_by_role(config, DEFAULT_SLAVE_ROLE_NAME)

def get_slave_ip_addresses(config):
    addresses = []
    reservations = get_slave_reservations(config)
    if reservations:
        for reservation in reservations:
            for instance in reservation.instances:
                if instance.ip_address and instance.state == 'running':
                    addresses.append({
                        "ip": instance.ip_address,
                        "ssh_ready": False
                    })
    return addresses

def wait_for_slave_ssh(config):
    port = 22
    addresses = get_slave_ip_addresses(config)
    working_addresses = 0
    print "Waiting for SSH connectivity to %d addresses" %(len(addresses),)

    while True:
        sleep(5)
        for address in addresses:
            if address['ssh_ready'] == True:
                continue
            try:
                s = socket.socket()
                s.connect((address['ip'], port))
                s.close()
                print "%s is ready for action" % (address['ip'])
                working_addresses = working_addresses + 1
                address['ssh_ready'] = True
            except Exception,e:
                s.close()

        if working_addresses == len(addresses):
            print "All slaves are responding to SSH"
            return

def create_master(config):
    return _run_instances_from_config(config, DEFAULT_MASTER_ROLE_NAME)


def create_slave(config):
    return _run_instances_from_config(config, DEFAULT_SLAVE_ROLE_NAME)


def update_master_security_group(config):
    aws_region = config.get('aws', 'aws_region')
    aws_access_key_id = config.get('aws', 'access_key_id')
    aws_secret_access_key = config.get('aws', 'secret_access_key')

    conn = connect_to_region(
        aws_region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key)

    slave_group = _get_security_group(conn, DEFAULT_SLAVE_ROLE_NAME)
    master_group = _get_security_group(conn, DEFAULT_MASTER_ROLE_NAME)

    if slave_group and master_group:
        try:
            master_group.authorize(src_group=slave_group)
        except:
            pass

        try:
            slave_group.authorize(src_group=master_group)
        except:
            pass


def _get_instances_by_role(config, role_name):
    aws_region = config.get('aws', 'aws_region')
    aws_access_key_id = config.get('aws', 'access_key_id')
    aws_secret_access_key = config.get('aws', 'secret_access_key')

    custom_tag = "tag:{0}".format(DEFAULT_CUSTOM_TAG_NAME)

    return _get_instances(
        aws_region, aws_access_key_id,
        aws_secret_access_key, {custom_tag: role_name})


def _get_instances(aws_region,
                   aws_access_key_id,
                   aws_secret_access_key,
                   filters):

    conn = connect_to_region(
        aws_region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key)

    return conn.get_all_instances(filters=filters)


def _run_instances_from_config(config, role_name):
    aws_region = config.get('aws', 'aws_region')
    aws_access_key_id = config.get('aws', 'access_key_id')
    aws_secret_access_key = config.get('aws', 'secret_access_key')
    ami_id = config.get('aws', 'ami_id')
    ami_instance_type = config.get('aws', 'ami_instance_type')
    aws_key_name = config.get('aws', 'aws_key_name', None)
    tag_dict = {DEFAULT_CUSTOM_TAG_NAME: role_name}

    security_group = _get_or_create_security_group_from_role(
        aws_region,
        aws_access_key_id,
        aws_secret_access_key,
        role_name)

    security_group_ids = [security_group.id] if security_group else []

    return _run_instances(
        aws_region,
        aws_access_key_id,
        aws_secret_access_key,
        ami_id,
        ami_instance_type,
        aws_key_name,
        tag_dict,
        security_group_ids)


def _run_instances(aws_region,
                   aws_access_key_id,
                   aws_secret_access_key,
                   ami_id,
                   ami_instance_type,
                   aws_key_name,
                   tag_dict,
                   security_group_ids):

    conn = connect_to_region(
        aws_region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key)

    reservation = conn.run_instances(
        image_id=ami_id,
        key_name=aws_key_name,
        security_group_ids=security_group_ids,
        instance_type=ami_instance_type).instances[0]

    _wait_for_instance_state(reservation, 'running')

    for tag, value in tag_dict.items():
        reservation.add_tag(tag, value)

    return reservation


def _wait_for_instance_state(instance, state, num_secs_to_sleep=20,
                             max_num_times=5):
    num_times = 0
    while True and num_times < max_num_times:
        instance.update()
        if state == instance.state:
            return
        else:
            num_times += 1
            sleep(num_secs_to_sleep)
    raise Exception


def _get_or_create_security_group_from_role(aws_region,
                                            aws_access_key_id,
                                            aws_secret_access_key,
                                            role_name):

    authorization_tuples = [('tcp', 22, 22, '0.0.0.0/0')]

    if role_name == DEFAULT_MASTER_ROLE_NAME:
        authorization_tuples.append(('tcp', 8089, 8089, '0.0.0.0/0'))

    return _get_or_create_security_group(
        aws_region,
        aws_access_key_id,
        aws_secret_access_key,
        role_name,
        role_name,
        authorization_tuples)


def _get_or_create_security_group(
        aws_region,
        aws_access_key_id,
        aws_secret_access_key,
        security_group_name,
        security_group_description,
        authorization_tuples=[('tcp', 22, 22, '0.0.0.0/0')]):

    conn = connect_to_region(
        aws_region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key)

    group = _get_security_group(conn, security_group_name)
    if not group:
        group = _create_security_group(conn,
                                       security_group_name,
                                       security_group_description,
                                       authorization_tuples)
    return group


def _get_security_group(conn, security_group_name):
    try:
        return conn.get_all_security_groups([security_group_name])[0]
    except:
        return None


def _create_security_group(conn,
                           group_name,
                           group_description,
                           authorization_tuples=[]):

    group = conn.create_security_group(group_name, group_description)
    for auth_tuple in authorization_tuples:
        group.authorize(*auth_tuple)
    return group


# vim: filetype=python
