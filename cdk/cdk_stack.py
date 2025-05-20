from aws_cdk import (
    Duration,
    Stack,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecr as ecr,
    aws_iam as iam,
    aws_cognito as cognito,
    aws_secretsmanager as secretsmanager,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_elasticloadbalancingv2 as elbv2,
    SecretValue,
    CfnOutput,
    RemovalPolicy,
    aws_appsync as appsync,
    aws_dynamodb as dynamodb,
    aws_opensearchserverless as opensearchserverless,
    aws_lambda as _lambda,
    aws_s3 as s3,
    aws_lambda_event_sources as lambda_events,
    CustomResource as CustomResource,
)
from constructs import Construct
from docker_app.config_file import Config
import json

CUSTOM_HEADER_NAME = "X-Custom-Header"


class CdkStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        prefix = Config.STACK_NAME

        # 1. Networking
        vpc = ec2.Vpc(
            self,
            f"{prefix}AppVpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=2,
            vpc_name=f"{prefix}-stl-vpc",
            nat_gateways=1,
        )
        ecs_security_group = ec2.SecurityGroup(
            self,
            f"{prefix}SecurityGroupECS",
            vpc=vpc,
            security_group_name=f"{prefix}-stl-ecs-sg",
        )
        alb_security_group = ec2.SecurityGroup(
            self,
            f"{prefix}SecurityGroupALB",
            vpc=vpc,
            security_group_name=f"{prefix}-stl-alb-sg",
        )
        ecs_security_group.add_ingress_rule(
            peer=alb_security_group,
            connection=ec2.Port.tcp(8501),
            description="ALB traffic",
        )

        # 2. Storage
        pdf_bucket = s3.Bucket(
            self,
            f"{prefix}KnowledgeBaseBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        conversation_table = dynamodb.Table(
            self,
            "ConversationTable",
            partition_key=dynamodb.Attribute(
                name="sessionId", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.NUMBER
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # 3. Security/IAM
        user_pool = cognito.UserPool(self, f"{prefix}UserPool")
        user_pool_client = cognito.UserPoolClient(
            self, f"{prefix}UserPoolClient", user_pool=user_pool, generate_secret=True
        )
        secret = secretsmanager.Secret(
            self,
            f"{prefix}ParamCognitoSecret",
            secret_object_value={
                "pool_id": SecretValue.unsafe_plain_text(user_pool.user_pool_id),
                "app_client_id": SecretValue.unsafe_plain_text(
                    user_pool_client.user_pool_client_id
                ),
                "app_client_secret": user_pool_client.user_pool_client_secret,
            },
            secret_name=Config.SECRETS_MANAGER_ID,
        )
        lambda_role = iam.Role(
            self,
            "LambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )
        lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            )
        )
        conversation_table.grant_read_write_data(lambda_role)
        lambda_role.add_to_policy(
            iam.PolicyStatement(actions=["bedrock:*"], resources=["*"])
        )
        lambda_role.add_to_policy(
            iam.PolicyStatement(actions=["es:*"], resources=["*"])
        )

        # 4. Compute
        cluster = ecs.Cluster(
            self, f"{prefix}Cluster", enable_fargate_capacity_providers=True, vpc=vpc
        )
        fargate_task_definition = ecs.FargateTaskDefinition(
            self, f"{prefix}WebappTaskDef", memory_limit_mib=512, cpu=256
        )
        # ecr_repo = ecr.Repository.from_repository_name(
        #     self,
        #     "StreamlitEcrRepo",
        #     "cdk-hnb659fds-container-assets-590183822512-us-east-1",
        # )
        # image = ecs.ContainerImage.from_ecr_repository(
        #     ecr_repo,
        #     tag="62639301904450f74e3b6e9f76a851539ac0a52199984eb0dc505a7f45e752b3",
        # )
        image = ecs.ContainerImage.from_asset("docker_app")
        fargate_task_definition.add_container(
            f"{prefix}WebContainer",
            image=image,
            port_mappings=[
                ecs.PortMapping(container_port=8501, protocol=ecs.Protocol.TCP)
            ],
            logging=ecs.LogDrivers.aws_logs(stream_prefix="WebContainerLogs"),
            environment={"PDF_BUCKET": pdf_bucket.bucket_name},
        )
        service = ecs.FargateService(
            self,
            f"{prefix}ECSService",
            cluster=cluster,
            task_definition=fargate_task_definition,
            service_name=f"{prefix}-stl-front",
            security_groups=[ecs_security_group],
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
        )
        bedrock_policy = iam.Policy(
            self,
            f"{prefix}BedrockPolicy",
            statements=[
                iam.PolicyStatement(actions=["bedrock:InvokeModel"], resources=["*"])
            ],
        )
        task_role = fargate_task_definition.task_role
        task_role.attach_inline_policy(bedrock_policy)
        secret.grant_read(task_role)
        pdf_bucket.grant_read_write(task_role)

        # 5. Integrations
        alb = elbv2.ApplicationLoadBalancer(
            self,
            f"{prefix}Alb",
            vpc=vpc,
            internet_facing=True,
            load_balancer_name=f"{prefix}-stl",
            security_group=alb_security_group,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )
        origin = origins.LoadBalancerV2Origin(
            alb,
            custom_headers={CUSTOM_HEADER_NAME: Config.CUSTOM_HEADER_VALUE},
            origin_shield_enabled=False,
            protocol_policy=cloudfront.OriginProtocolPolicy.HTTP_ONLY,
        )
        cloudfront_distribution = cloudfront.Distribution(
            self,
            f"{prefix}CfDist",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origin,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
            ),
        )
        http_listener = alb.add_listener(f"{prefix}HttpListener", port=80, open=True)
        http_listener.add_targets(
            f"{prefix}TargetGroup",
            target_group_name=f"{prefix}-tg",
            port=8501,
            priority=1,
            conditions=[
                elbv2.ListenerCondition.http_header(
                    CUSTOM_HEADER_NAME, [Config.CUSTOM_HEADER_VALUE]
                )
            ],
            protocol=elbv2.ApplicationProtocol.HTTP,
            targets=[service],
        )
        http_listener.add_action(
            "default-action",
            action=elbv2.ListenerAction.fixed_response(
                status_code=403, content_type="text/plain", message_body="Access denied"
            ),
        )

        # # 1. Encryption policy
        # encryption_policy = opensearchserverless.CfnSecurityPolicy(
        #     self,
        #     "EncryptionPolicy",
        #     name=f"ck-assign-encryption-policy",
        #     type="encryption",
        #     description="Encryption policy for vector search collection",
        #     policy=json.dumps(
        #         {
        #             "Rules": [
        #                 {
        #                     "ResourceType": "collection",
        #                     "Resource": [f"collection/ck-assign-vector-*"],
        #                 }
        #             ],
        #             "AWSOwnedKey": True,
        #         }
        #     ),
        # )

        # # 2. Network policy - Allow access within VPC and from Lambda
        # network_policy = opensearchserverless.CfnSecurityPolicy(
        #     self,
        #     "NetworkPolicy",
        #     name=f"ck-assign-network-policy",
        #     type="network",
        #     description="Network policy for vector search collection",
        #     policy=json.dumps(
        #         [
        #             {
        #                 "Description": "Access from VPC",
        #                 "Rules": [
        #                     {
        #                         "ResourceType": "collection",
        #                         "Resource": [f"collection/ck-assign-vector-*"],
        #                     }
        #                 ],
        #                 "AllowFromPublic": True,
        #             }
        #         ]
        #     ),
        # )

        # # Collection (must be created after the encryption policy)
        # vector_collection = opensearchserverless.CfnCollection(
        #     self,
        #     "VectorCollection",
        #     name=f"ck-assign-vector-collection",
        #     type="VECTORSEARCH",
        #     description="Serverless vector search collection for RAG",
        # )

        # # Add explicit dependencies to ensure proper creation order
        # vector_collection.add_dependency(encryption_policy)
        # vector_collection.add_dependency(network_policy)

        # # Create index configuration for vector embeddings
        # index_lambda = _lambda.Function(
        #     self,
        #     "CreateVectorIndexLambda",
        #     runtime=_lambda.Runtime.PYTHON_3_12,
        #     handler="create_index.lambda_handler",
        #     code=_lambda.Code.from_asset("docker_app/lambda"),
        #     environment={
        #         "OPENSEARCH_HOST": f"{vector_collection.attr_collection_endpoint}",
        #         "OPENSEARCH_INDEX": Config.OPENSEARCH_INDEX_NAME,
        #         "VECTOR_DIMENSION": "1536",  # Claude/Bedrock embedding dimension
        #     },
        #     role=lambda_role,
        #     timeout=Duration.seconds(30),
        # )

        # # Add a custom resource to create the vector index when deploying
        # index_resource = CustomResource(
        #     self,
        #     "VectorIndexResource",
        #     service_token=index_lambda.function_arn,
        #     properties={
        #         "CollectionId": vector_collection.attr_id,
        #     },
        # )

        # opensearch_host = f"{vector_collection.attr_collection_endpoint}"

        # In your CDK stack
        rag_lambda = _lambda.Function(
            self,
            f"{prefix}RAGLambdaFunction",
            function_name=f"{prefix}RAGLambdaFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="lib.lambda_handler",
            code=_lambda.Code.from_asset("docker_app/lambda"),
            environment={
                "TABLE_NAME": conversation_table.table_name,
            },
            role=lambda_role,
        )
        rag_lambda.grant_invoke(task_role)
        opensearch_layer = _lambda.LayerVersion(
            self,
            "OpenSearchLayer",
            code=_lambda.Code.from_asset("lambda_layer/layer.zip"),
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_12],
        )

        rag_lambda.add_layers(opensearch_layer)
        ingest_lambda = _lambda.Function(
            self,
            f"{prefix}IngestPdfLambda",
            function_name=f"{prefix}IngestPdfLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="ingest_pdf.lambda_handler",
            code=_lambda.Code.from_asset("docker_app/lambda"),
            environment={
                # "OPENSEARCH_HOST": opensearch_host,
                # "OPENSEARCH_INDEX": Config.OPENSEARCH_INDEX_NAME,
                "BEDROCK_REGION": Config.BEDROCK_REGION,
                "BUCKET_NAME": pdf_bucket.bucket_name,
            },
            role=lambda_role,
        )
        ingest_lambda.add_layers(opensearch_layer)
        pdf_bucket.grant_read(ingest_lambda)
        ingest_lambda.add_event_source(
            lambda_events.S3EventSource(
                pdf_bucket,
                events=[s3.EventType.OBJECT_CREATED],
                filters=[s3.NotificationKeyFilter(suffix=".pdf")],
            )
        )
        history_lambda = _lambda.Function(
            self,
            f"{prefix}GetHistoryLambda",
            function_name=f"{prefix}GetHistoryLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="get_history_lambda.lambda_handler",
            code=_lambda.Code.from_asset("docker_app/lambda"),
            environment={"TABLE_NAME": conversation_table.table_name},
            role=lambda_role,
        )
        history_lambda.grant_invoke(task_role)
        api = appsync.GraphqlApi(
            self,
            "RAGAppSyncAPI",
            name="RAGAppSyncAPI",
            definition=appsync.Definition.from_file(
                "docker_app/graphql/schema.graphql"
            ),
            authorization_config=appsync.AuthorizationConfig(
                default_authorization=appsync.AuthorizationMode(
                    authorization_type=appsync.AuthorizationType.USER_POOL,
                    user_pool_config=appsync.UserPoolConfig(user_pool=user_pool),
                )
            ),
            xray_enabled=True,
        )
        lambda_ds = api.add_lambda_data_source("lambdaDatasource", rag_lambda)
        lambda_ds.create_resolver(
            id="AskQuestionResolver", type_name="Query", field_name="askQuestion"
        )

        # 6. Outputs
        CfnOutput(
            self, "CloudFrontDistributionURL", value=cloudfront_distribution.domain_name
        )
        CfnOutput(self, "CognitoPoolId", value=user_pool.user_pool_id)
        CfnOutput(self, "KnowledgeBaseBucketName", value=pdf_bucket.bucket_name)
        CfnOutput(self, "TableName", value=conversation_table.table_name)
        # CfnOutput(self, "OPENSEARCH_HOST", value=opensearch_host)
        CfnOutput(self, "OPENSEARCH_INDEX_NAME", value=Config.OPENSEARCH_INDEX_NAME)
