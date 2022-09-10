#!/usr/bin/env python3

import sys, json, pynetbox, os, requests
from argparse import ArgumentParser
from tabulate import tabulate
from util import *

checker = ArgumentParser(
        description='AWS Checker',# {{{
        epilog='Author: @fatah.hafidz',
        prog='aws-checker'
    )
subcom = checker.add_subparsers(title='subcommand', prog='aws-checker', dest='subcommand')# }}}
def subcommand(args=[], parent=subcom):
    def decorator(func):# {{{
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        parser.add_argument('-p', '--profile', default='default', help='profile name', required=False)
        parser.add_argument('-r', '--region', metavar='region', default='ap-southeast-1', help='region name', required=False)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
    return decorator# }}}

'''zabbix'''
@subcommand([
    argument('-t', '--tag',help='tag for project',required=False),#{{{
    argument('-a', '--acc',help='which account to use',default='main',required=False),
    argument('-f', '--fields', nargs="+", help='fields name', default=['Metric','prev','last'],required=False)
    ])
def zabbix(args):
    url = '' if args.acc == '' else ''
    z = get_zabbix(args,url)
    renderer(args,z,args.subcommand)#}}}

'''portainer'''
@subcommand([
    argument('-t', '--team', help='project', required=False),# {{{
    argument('-s', '--status', help='container status', action='store_true', required=False),
    argument('-f', '--fields', nargs="+", type=str, help='field name', required=False),
    ])
def portainer(args):
    print(portainer_token(args))
    #token = ''
    #base = 'https://'+teams[team]+'/api'
    #endpoints= requests.get(base+'/endpoints',headers={'Authorization': 'Bearer '+token}).json()
    #data = []
    #for end in endpoints:
    #    if args.status:
    #        r = requests.get(base+'/endpoints/{}/docker/containers/json'.format(end['Id']),headers={'Authorization': 'Bearer '+token}).json()
    #        for item in r:
    #            data.append(
    #                    {
    #                        'Name': item['Names'][0],
    #                        'State': item['State'],
    #                        'Status': item['Status'],
    #                        'Env': end['Name']
    #                    }
    #                )
    #            args.fields = ['State','Status','Env']
    #    else:
    #        data.append(
    #                {
    #                    'Name': end['Name'],
    #                    'Id': "{}".format(end['Id']),
    #                    'Url': end['URL'],
    #                    'Images': "{}".format(end['Snapshots'][0]['ImageCount']),
    #                    'Running': "{}".format(end['Snapshots'][0]['RunningContainerCount']),
    #                }
    #            )
    #        args.fields = ['Id','Url','Images','Running']
    #renderer(args, data,args.subcommand)
    # }}}

'''netbox'''
@subcommand([
    argument('-s', '--secret', help='get seczret for projezct', required=False),# {{{
    argument('-f', '--fields', metavar='fields', nargs="+", type=str, default=['Role','Pass'], help='field name', required=False)
    ])
def netbox(args):
    #s = requests.Session()
    #s.cert = '/home/z3r0/.tsh/keys/teleport.fpl.expert/fatah-app/teleport-1/netbox-x509.pem', '/home/z3r0/.tsh/keys/teleport.fpl.expert/fatah'
    nb = pynetbox.api(
            url='',
            token='',
            private_key_file='',
        )
    #nb.http_session = s
    #devices = nb.dcim.devices.filter(args.secret)
    vms = nb.virtualization.virtual_machines.filter(args.secret)
    vm_list = []
    for vm in vms:
        vm_secrets = nb.secrets.secrets.filter(virtual_machine=vm.name)
        data_list = []
        for secret in vm_secrets:
            res = json.dumps(dict(secret.assigned_object))
            data_list.append({
                    'Name': secret['name'],
                    'Role': secret['role']['name'],
                    'Pass': secret['plaintext']
                })
        renderer(args, data_list,vm.name)
        #}}}

'''tfstate'''
@subcommand([
    argument('-pr', '--project', help='project name', required=False),# {{{
    argument('-rds', '--rds', help='get rds password for admin', required=False, action='store_true'),
    argument('-f', '--fields', metavar='fields', nargs="+", help='field name', required=False)
    ])
def tfstate(args):
    head = ['Priv Key'] if args.rds is False else ['Name','Username',args.project+'_admin pass','Address']
    proj = s3_list_obj(args)
    data,args.fields = pem(args,proj)
    renderer(args,data,args.subcommand)#}}}

'''IAM'''
@subcommand([
    argument('-u', '--user', metavar="user", help='iam user name', required=False),# {{{
    argument('--sts', '--sts', help='create sts for user', action='store_true'),
    argument('-f', '--fields', metavar='fields', nargs="+", type=str, default=['AccessKeyId','Status'], help='field name', required=False)
    ])
def iam(args):
    user = args.user
    iam = session(args,'iam')
    acc = ''
    if args.sts:
        try:
            managed_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "VisualEditor0",
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:ListBucket"
                        ],
                        "Resource": [
                            "arn:aws:s3:::"+user+"-pvt",
                            "arn:aws:s3:::"+user+"-pvt/*"
                        ]
                    }
                ]
            }
            '''create policy'''
            role_policy = iam.create_policy(
                PolicyName=user+'-s3-sts',
                PolicyDocument=json.dumps(managed_policy),
                Description='STS policy for '+user
                )

            assume_pol = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::"+acc+":root"
                            },
                            "Action": "sts:AssumeRole",
                            "Condition": {}
                        }
                    ]
                }
            '''create role'''
            user_role = iam.create_role(
                RoleName=user+'-s3-role',
                AssumeRolePolicyDocument=json.dumps(assume_pol)
            )
            '''attach policy to role'''
            iam.attach_role_policy(
                    RoleName=user_role['Role']['RoleName'],
                    PolicyArn=role_policy['Policy']['Arn']
                )
           
            sts_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "VisualEditor0",
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": "{}".format(user_role['Role']['Arn'])
                    }
                ]
            }
           
            iam.create_user(UserName=user)
            respond = iam.create_access_key(UserName=user)
            iam.put_user_policy(
                UserName=user,
                PolicyName=user+'-sts',
                PolicyDocument=json.dumps(sts_policy),
            )
            tbl = tabulate([['AccessKeyId',respond['AccessKey']['AccessKeyId']],['SecretAccessKey',respond['AccessKey']['SecretAccessKey']],['Role',user_role['Role']['Arn']]],headers=['Key','Value'], tablefmt='rounded_outline')
            print(tbl)
            pyperclip.copy(tbl)
        except Exception as e:
            print(e)
            exit(1)
    else:
        try:
            users = iam_user_list(args)
            user_list = []
            for user in users:
                response = iam.list_access_keys(UserName=user)
                if response['AccessKeyMetadata'] is not None:
                    data = []
                    for access_key in response['AccessKeyMetadata']:
                        data.append(
                            {
                                'Name': access_key['UserName'],
                                'AccessKeyId': access_key['AccessKeyId'], 
                                'Status': access_key['Status'], 
                                #access_key['CreateDate']
                            }
                        )
                else:
                    return False
                for x in data:
                    user_list.append(x)
            renderer(args,user_list,args.subcommand)
        except Exception as e:
            print(e)
            return False# }}}

'''EC2'''
@subcommand([
    argument('-i', '--instance', metavar='instance', help='instance name', required=False),# {{{ 
    argument('-f', '--fields', metavar='fields', nargs="+", type=str, default=['IP', 'AZ', 'Status', 'Type', 'Launch'], help='field name', required=False)
    ])
def ec2(args):
    instance_name = args.instance
    args.region = region_code(args.region)
    try:
        ec2 = session(args,'ec2')
        response = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [
                        '*'+instance_name+'*'
                    ]
                }
            ]
        )
        if response['Reservations']:
            data = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            data.append(
                                {
                                    'Name': tag['Value'],
                                    'IP': instance['PublicIpAddress'] if instance.get('PublicIpAddress') else instance['PrivateIpAddress'],
                                    'AZ': instance['Placement']['AvailabilityZone'], 
                                    'Status': instance['State']['Name'], 
                                    'Type': instance['InstanceType'],
                                    'Launch': instance['LaunchTime'].strftime("%Y-%m-%d %H:%M:%S"),
                                }
                            )
            renderer(args,data,args.subcommand)
        else:
            return False
    except Exception as e:
        print(e)
        return False
        #if e.response['Error']['Code'] == 'AccessDenied':
        #    print('{}: Use VPN Machaaa'.format(e.response['Error']['Code']))
        #    return False# }}}

'''RDS'''
@subcommand([
    argument('-d', '--db', metavar='db', help='db name', required=False),# {{{
    argument('-f', '--fields', metavar='fields', nargs="+", type=str, default=['Status', 'Endpoint', 'Version', 'Class', 'Public','CA'], help='field name', required=False)
    ])
def rds(args):
    try:
        args.region = region_code(args.region)
        rds = session(args,'rds')
        dbs = db_list(args)
        db_lists = []
        for db in dbs:
            response = rds.describe_db_instances(DBInstanceIdentifier=db)
            if response['DBInstances']:
                data = []
                for db_instance in response['DBInstances']:
                    data.append(
                            {
                                'Name': db_instance['DBInstanceIdentifier'], 
                                'Status': db_instance['DBInstanceStatus'], 
                                'Endpoint': db_instance['Endpoint']['Address'], 
                                'Version': db_instance['EngineVersion'], 
                                'Class': db_instance['DBInstanceClass'], 
                                'Public': "{}".format(db_instance['PubliclyAccessible']),
                                'CA' :db_instance['CACertificateIdentifier'], 
                            }
                    )
                for x in data:
                    db_lists.append(x)
        renderer(args,db_lists,args.subcommand)
    except Exception as e:
        print(e)
        return False# }}}

'''S3'''
@subcommand([
    argument('-b', '--bucket', metavar='bucket', help='bucket name', required=False),# {{{
    argument('-s', '--size', help='include bucket size in output', required=False, action='store_true'),
    argument('-f', '--fields', metavar='fields', nargs="+", default=['Size'],type=str, help='field name', required=False)
    ])
def s3(args):
    buckets = s3_list(args)
    #bucket_list = []
    #for bucket in buckets:
    #    lister = bucket
    #bucket_list.append(lister)
    bucket = [bucket for bucket in buckets]
    renderer(args,bucket,args.subcommand)#}}}

'''CF'''
@subcommand([
    argument('-z', '--zone', metavar='domain name', help='zone name', required=False),# {{{
    argument('-f', '--fields', metavar='fields', nargs="+", type=str, default=['Content','Type','Acc','Login'], help='field name', required=False)
    ])
def cf(args):
    (zone_id,
    zone_name,
    zone_type,
    zone_owner,
    zone_plan,
    zone_account,
    dns_records,
    token) = fetch_zones(args)
    data = []
    for dns in dns_records:
       data.append(
            {
                'Name': dns["name"],
                'Content': dns["content"],
                'Type': dns["type"],
                'Acc': zone_account["name"],
                'Login': token
            }
        )
    renderer(args,data,args.subcommand)#}}}
if __name__ == "__main__":
    args = checker.parse_args()# {{{
    if args.subcommand is None:
        checker.print_help()
    else:
        if len(sys.argv) > 2:
            args.func(args)
        else:
            args = [args.subcommand]
            args.append('-h')
            checker.parse_args(args)# }}}

#lt vim:fileencoding=utf-8:ft=python:foldmethod=marker
