#!/bin/bash
# SKSecurity Enterprise - Docker Build Script

set -e

# Configuration
IMAGE_NAME="smilintu/sksecurity"
VERSION="1.0.0"
DOCKER_HUB_ORG="smilintu"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🐳 SKSecurity Docker Build Script${NC}"
echo "================================="

# Check if Docker is installed and running
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found. Please install Docker first.${NC}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}❌ Docker daemon not running. Please start Docker.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker is available${NC}"

# Build main image
echo -e "${BLUE}🏗️ Building main image...${NC}"
docker build -f docker/Dockerfile -t "${IMAGE_NAME}:${VERSION}" -t "${IMAGE_NAME}:latest" .

# Build Alpine variant
echo -e "${BLUE}🏗️ Building Alpine variant...${NC}"
docker build -f docker/Dockerfile.alpine -t "${IMAGE_NAME}:${VERSION}-alpine" -t "${IMAGE_NAME}:alpine" .

# Show built images
echo -e "${GREEN}📦 Built images:${NC}"
docker images | grep "${IMAGE_NAME}" | head -4

# Test the images
echo -e "${BLUE}🧪 Testing main image...${NC}"
if docker run --rm "${IMAGE_NAME}:latest" sksecurity --version; then
    echo -e "${GREEN}✅ Main image test passed${NC}"
else
    echo -e "${RED}❌ Main image test failed${NC}"
    exit 1
fi

echo -e "${BLUE}🧪 Testing Alpine image...${NC}"
if docker run --rm "${IMAGE_NAME}:alpine" sksecurity --version; then
    echo -e "${GREEN}✅ Alpine image test passed${NC}"
else
    echo -e "${RED}❌ Alpine image test failed${NC}"
    exit 1
fi

# Show image sizes
echo -e "${BLUE}📏 Image sizes:${NC}"
docker images "${IMAGE_NAME}" --format "table {{.Tag}}\t{{.Size}}"

echo ""
echo -e "${GREEN}🎉 Build completed successfully!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Test locally: docker run -p 8888:8888 ${IMAGE_NAME}:latest"
echo "2. Push to Docker Hub: ./scripts/push-docker.sh"
echo "3. Deploy: docker-compose up -d"

# Offer to run container for testing
read -p "🚀 Would you like to run the container for testing? (y/N): " -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}🚀 Starting test container...${NC}"
    echo "Dashboard will be available at: http://localhost:8888"
    echo "Press Ctrl+C to stop"
    docker run --rm -p 8888:8888 "${IMAGE_NAME}:latest"
fi