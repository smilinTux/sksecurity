#!/bin/bash
# SKSecurity Enterprise - Docker Hub Push Script

set -e

# Configuration
IMAGE_NAME="smilintu/sksecurity"
VERSION="1.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🐳 SKSecurity Docker Push Script${NC}"
echo "================================"

# Check if logged into Docker Hub
if ! docker info | grep -q "Username"; then
    echo -e "${YELLOW}🔐 Please log into Docker Hub first:${NC}"
    echo "docker login"
    read -p "Press Enter after logging in..."
fi

# Verify images exist
if ! docker images "${IMAGE_NAME}:latest" | grep -q "latest"; then
    echo -e "${RED}❌ Main image not found. Run ./scripts/build-docker.sh first${NC}"
    exit 1
fi

if ! docker images "${IMAGE_NAME}:alpine" | grep -q "alpine"; then
    echo -e "${RED}❌ Alpine image not found. Run ./scripts/build-docker.sh first${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Images found locally${NC}"

# Push main images
echo -e "${BLUE}📤 Pushing main image (latest)...${NC}"
docker push "${IMAGE_NAME}:latest"

echo -e "${BLUE}📤 Pushing main image (${VERSION})...${NC}"
docker push "${IMAGE_NAME}:${VERSION}"

# Push Alpine images
echo -e "${BLUE}📤 Pushing Alpine image (alpine)...${NC}"
docker push "${IMAGE_NAME}:alpine"

echo -e "${BLUE}📤 Pushing Alpine image (${VERSION}-alpine)...${NC}"
docker push "${IMAGE_NAME}:${VERSION}-alpine"

# Verify pushed images
echo -e "${BLUE}🔍 Verifying pushed images...${NC}"
if curl -s "https://hub.docker.com/v2/repositories/${IMAGE_NAME}/tags/" | grep -q "latest"; then
    echo -e "${GREEN}✅ Images successfully pushed to Docker Hub${NC}"
else
    echo -e "${YELLOW}⚠️ Unable to verify push (but likely successful)${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Push completed successfully!${NC}"
echo ""
echo -e "${YELLOW}📍 Your images are now available:${NC}"
echo "• docker pull ${IMAGE_NAME}:latest"
echo "• docker pull ${IMAGE_NAME}:${VERSION}"
echo "• docker pull ${IMAGE_NAME}:alpine"
echo "• docker pull ${IMAGE_NAME}:${VERSION}-alpine"
echo ""
echo -e "${BLUE}🌐 Docker Hub page:${NC}"
echo "https://hub.docker.com/r/smilintu/sksecurity"
echo ""
echo -e "${YELLOW}📋 Example usage:${NC}"
echo "docker run -p 8888:8888 ${IMAGE_NAME}:latest"
echo "docker-compose -f docker/docker-compose.prod.yml up -d"