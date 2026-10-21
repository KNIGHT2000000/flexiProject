import os
import yaml
import pytest

TEMPLATE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "template.yaml")
)
SAMCONFIG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "samconfig.toml")
)


@pytest.fixture(scope="module")
def sam_template():
    assert os.path.exists(TEMPLATE_PATH), f"template.yaml not found at {TEMPLATE_PATH}"
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        # Load yaml using PyYAML with safe loader (ignoring CloudFormation custom tags)
        class CloudFormationLoader(yaml.SafeLoader):
            pass

        # Register common AWS CloudFormation intrinsic tags
        tags = [
            "!Sub", "!Ref", "!GetAtt", "!Split", "!Join", "!Select",
            "!FindInMap", "!Base64", "!Cidr", "!And", "!Equals", "!If",
            "!Not", "!Or", "!Condition"
        ]
        for tag in tags:
            CloudFormationLoader.add_constructor(
                tag,
                lambda loader, node: (
                    loader.construct_sequence(node)
                    if isinstance(node, yaml.SequenceNode)
                    else loader.construct_scalar(node)
                    if isinstance(node, yaml.ScalarNode)
                    else loader.construct_mapping(node)
                ),
            )

        template = yaml.load(f, Loader=CloudFormationLoader)
    assert template is not None, "Failed to parse template.yaml"
    return template


def test_sam_template_header_and_transform(sam_template):
    assert sam_template.get("AWSTemplateFormatVersion") == "2010-09-09"
    assert sam_template.get("Transform") == "AWS::Serverless-2016-10-31"
    assert "Description" in sam_template


def test_sam_template_parameters(sam_template):
    parameters = sam_template.get("Parameters", {})
    required_params = [
        "Environment",
        "CorsAllowedOrigins",
        "JwtSecret",
        "DatabaseUrl",
        "VirusTotalApiKey",
        "GoogleSafeBrowsingApiKey",
        "LogRetentionInDays",
    ]
    for param in required_params:
        assert param in parameters, f"Parameter '{param}' missing from template.yaml"

    assert parameters["Environment"]["AllowedValues"] == ["staging", "prod"]
    assert parameters["JwtSecret"].get("NoEcho") is True
    assert parameters["LogRetentionInDays"]["Default"] == 14


def test_sam_api_gateway_resource(sam_template):
    resources = sam_template.get("Resources", {})
    assert "ApiGatewayApi" in resources, "ApiGatewayApi resource missing"
    api = resources["ApiGatewayApi"]
    assert api["Type"] == "AWS::Serverless::HttpApi"
    props = api["Properties"]
    assert "CorsConfiguration" in props
    cors = props["CorsConfiguration"]
    assert "X-Request-ID" in cors.get("ExposeHeaders", [])
    assert props.get("DefaultRouteSettings", {}).get("ThrottlingBurstLimit") == 100


def test_sam_fastapi_lambda_resource(sam_template):
    resources = sam_template.get("Resources", {})
    assert "FastApiFunction" in resources, "FastApiFunction resource missing"
    fn = resources["FastApiFunction"]
    assert fn["Type"] == "AWS::Serverless::Function"
    props = fn["Properties"]
    assert props["Handler"] == "app.lambda_handler.handler"
    assert props["CodeUri"] == "backend/"

    events = props.get("Events", {})
    assert "RootRoute" in events
    assert "ProxyRoute" in events
    assert events["RootRoute"]["Properties"]["Path"] == "/"
    assert events["ProxyRoute"]["Properties"]["Path"] == "/{proxy+}"


def test_sam_frontend_s3_bucket_security(sam_template):
    resources = sam_template.get("Resources", {})
    assert "FrontendBucket" in resources, "FrontendBucket resource missing"
    bucket = resources["FrontendBucket"]
    assert bucket["Type"] == "AWS::S3::Bucket"
    props = bucket["Properties"]

    # Security: All 4 public access block settings must be enabled
    pab = props.get("PublicAccessBlockConfiguration", {})
    assert pab.get("BlockPublicAcls") is True
    assert pab.get("BlockPublicPolicy") is True
    assert pab.get("IgnorePublicAcls") is True
    assert pab.get("RestrictPublicBuckets") is True

    # Security: Default server-side encryption
    enc = props.get("BucketEncryption", {})
    rules = enc.get("ServerSideEncryptionConfiguration", [])
    assert len(rules) >= 1
    assert rules[0]["ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"


def test_sam_cloudfront_and_oac_configuration(sam_template):
    resources = sam_template.get("Resources", {})
    assert "CloudFrontOAC" in resources, "CloudFrontOAC resource missing"
    oac = resources["CloudFrontOAC"]
    assert oac["Type"] == "AWS::CloudFront::OriginAccessControl"
    assert oac["Properties"]["OriginAccessControlConfig"]["OriginAccessControlOriginType"] == "s3"

    assert "FrontendDistribution" in resources, "FrontendDistribution resource missing"
    dist = resources["FrontendDistribution"]
    assert dist["Type"] == "AWS::CloudFront::Distribution"
    dist_config = dist["Properties"]["DistributionConfig"]

    # Viewer protocol redirect to HTTPS
    dcb = dist_config.get("DefaultCacheBehavior", {})
    assert dcb.get("ViewerProtocolPolicy") == "redirect-to-https"

    # SPA routing custom error responses for 403 and 404
    error_responses = dist_config.get("CustomErrorResponses", [])
    error_codes = [r.get("ErrorCode") for r in error_responses]
    assert 403 in error_codes
    assert 404 in error_codes
    for r in error_responses:
        assert r.get("ResponsePagePath") == "/index.html"
        assert r.get("ResponseCode") == 200


def test_sam_s3_bucket_policy(sam_template):
    resources = sam_template.get("Resources", {})
    assert "FrontendBucketPolicy" in resources, "FrontendBucketPolicy resource missing"
    policy = resources["FrontendBucketPolicy"]
    assert policy["Type"] == "AWS::S3::BucketPolicy"
    doc = policy["Properties"]["PolicyDocument"]
    stmt = doc["Statement"][0]
    assert stmt["Effect"] == "Allow"
    assert stmt["Principal"]["Service"] == "cloudfront.amazonaws.com"
    assert stmt["Action"] == "s3:GetObject"


def test_sam_template_outputs(sam_template):
    outputs = sam_template.get("Outputs", {})
    required_outputs = [
        "ApiEndpoint",
        "FastApiFunctionArn",
        "CloudFrontDistributionId",
        "CloudFrontDomain",
        "FrontendBucketName",
    ]
    for key in required_outputs:
        assert key in outputs, f"Output '{key}' missing from template.yaml"


def test_samconfig_exists():
    assert os.path.exists(SAMCONFIG_PATH), f"samconfig.toml not found at {SAMCONFIG_PATH}"
    with open(SAMCONFIG_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    assert "[staging]" in content
    assert "[prod]" in content
    assert "phishguard-cloud-staging" in content
    assert "phishguard-cloud-prod" in content
