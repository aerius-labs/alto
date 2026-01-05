#!/bin/bash
# test_verification.sh
# Comprehensive test script for QMDB proof generation and verification

BASE_URL="http://localhost:4001"
PASSED=0
FAILED=0

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  QMDB Proof Verification Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to print test header
print_test_header() {
    echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Function to check if API is available
check_api() {
    echo "Checking API availability..."
    if curl -s -f "$BASE_URL/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ API is available${NC}"
        return 0
    else
        echo -e "${RED}✗ API is not available at $BASE_URL${NC}"
        echo "Please make sure the API server is running."
        exit 1
    fi
}

# Function to get state root
get_state_root() {
    echo "Fetching current state root..."
    STATE_ROOT_RESPONSE=$(curl -s "$BASE_URL/state-root")
    CURRENT_STATE_ROOT=$(echo "$STATE_ROOT_RESPONSE" | jq -r '.state_root')
    echo -e "State Root: ${BLUE}$CURRENT_STATE_ROOT${NC}"
    echo ""
}

# Check API availability
check_api
get_state_root

# Test 1: Get and verify proof for account 0
print_test_header "Test 1: Balance Proof for Account 0"

echo "Step 1: Getting proof for account 0..."
PROOF_RESPONSE=$(curl -s "$BASE_URL/proof/balance/0")

if [ -z "$PROOF_RESPONSE" ] || [ "$PROOF_RESPONSE" == "null" ]; then
    echo -e "${RED}✗ Failed to get proof${NC}"
    ((FAILED++))
else
    echo -e "${GREEN}✓ Proof retrieved successfully${NC}"
    echo ""
    echo "Proof Details:"
    echo "$PROOF_RESPONSE" | jq '.'
    
    ACCOUNT=$(echo "$PROOF_RESPONSE" | jq -r '.account')
    BALANCE=$(echo "$PROOF_RESPONSE" | jq -r '.balance')
    PROOF=$(echo "$PROOF_RESPONSE" | jq -r '.proof')
    STATE_ROOT=$(echo "$PROOF_RESPONSE" | jq -r '.state_root')
    
    echo ""
    echo "Extracted Values:"
    echo "  Account ID: $ACCOUNT"
    echo "  Balance: $BALANCE"
    echo "  Proof Length: ${#PROOF} characters"
    echo "  State Root: $STATE_ROOT"
    
    echo ""
    echo "Step 2: Verifying proof with correct values..."
    VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/verify/proof" \
      -H "Content-Type: application/json" \
      -d "{
        \"account\": $ACCOUNT,
        \"balance\": $BALANCE,
        \"proof\": \"$PROOF\",
        \"state_root\": \"$STATE_ROOT\"
      }")
    
    echo "$VERIFY_RESPONSE" | jq '.'
    
    VALID=$(echo "$VERIFY_RESPONSE" | jq -r '.valid')
    MESSAGE=$(echo "$VERIFY_RESPONSE" | jq -r '.message')
    
    if [ "$VALID" == "true" ]; then
        echo -e "${GREEN}✓ Proof verification SUCCESSFUL${NC}"
        echo -e "  Message: $MESSAGE"
        ((PASSED++))
    else
        echo -e "${RED}✗ Proof verification FAILED${NC}"
        echo -e "  Message: $MESSAGE"
        ((FAILED++))
    fi
fi

# Test 2: Verify with wrong balance
print_test_header "Test 2: Invalid Proof (Wrong Balance)"

if [ -n "$PROOF" ] && [ -n "$STATE_ROOT" ]; then
    echo "Testing with incorrect balance (9999 instead of $BALANCE)..."
    WRONG_RESPONSE=$(curl -s -X POST "$BASE_URL/verify/proof" \
      -H "Content-Type: application/json" \
      -d "{
        \"account\": $ACCOUNT,
        \"balance\": 9999,
        \"proof\": \"$PROOF\",
        \"state_root\": \"$STATE_ROOT\"
      }")
    
    echo "$WRONG_RESPONSE" | jq '.'
    
    WRONG_VALID=$(echo "$WRONG_RESPONSE" | jq -r '.valid')
    WRONG_MESSAGE=$(echo "$WRONG_RESPONSE" | jq -r '.message')
    
    if [ "$WRONG_VALID" == "false" ]; then
        echo -e "${GREEN}✓ Correctly rejected invalid proof${NC}"
        echo -e "  Message: $WRONG_MESSAGE"
        ((PASSED++))
    else
        echo -e "${RED}✗ Should have rejected invalid proof${NC}"
        ((FAILED++))
    fi
else
    echo -e "${RED}✗ Skipped: No proof available from previous test${NC}"
    ((FAILED++))
fi

# Test 3: Verify with wrong state root
print_test_header "Test 3: Invalid Proof (Wrong State Root)"

if [ -n "$PROOF" ] && [ -n "$BALANCE" ]; then
    echo "Testing with incorrect state root..."
    WRONG_STATE_ROOT="0000000000000000000000000000000000000000000000000000000000000000"
    WRONG_STATE_RESPONSE=$(curl -s -X POST "$BASE_URL/verify/proof" \
      -H "Content-Type: application/json" \
      -d "{
        \"account\": $ACCOUNT,
        \"balance\": $BALANCE,
        \"proof\": \"$PROOF\",
        \"state_root\": \"$WRONG_STATE_ROOT\"
      }")
    
    echo "$WRONG_STATE_RESPONSE" | jq '.'
    
    WRONG_STATE_VALID=$(echo "$WRONG_STATE_RESPONSE" | jq -r '.valid')
    
    if [ "$WRONG_STATE_VALID" == "false" ]; then
        echo -e "${GREEN}✓ Correctly rejected proof with wrong state root${NC}"
        ((PASSED++))
    else
        echo -e "${RED}✗ Should have rejected proof with wrong state root${NC}"
        ((FAILED++))
    fi
else
    echo -e "${RED}✗ Skipped: No proof available from previous test${NC}"
    ((FAILED++))
fi

# Test 4: Test multiple accounts
print_test_header "Test 4: Multiple Account Proofs"

ACCOUNTS=(0 1 2 3 4 5)
MULTI_PASSED=0
MULTI_FAILED=0

for acc in "${ACCOUNTS[@]}"; do
    echo ""
    echo "Testing account $acc..."
    
    ACC_PROOF_RESPONSE=$(curl -s "$BASE_URL/proof/balance/$acc")
    
    if [ -z "$ACC_PROOF_RESPONSE" ] || echo "$ACC_PROOF_RESPONSE" | jq -e '.account == null' > /dev/null 2>&1; then
        echo -e "  ${YELLOW}⚠ Account $acc not found (may not exist)${NC}"
        continue
    fi
    
    ACC_ACCOUNT=$(echo "$ACC_PROOF_RESPONSE" | jq -r '.account')
    ACC_BALANCE=$(echo "$ACC_PROOF_RESPONSE" | jq -r '.balance')
    ACC_PROOF=$(echo "$ACC_PROOF_RESPONSE" | jq -r '.proof')
    ACC_STATE_ROOT=$(echo "$ACC_PROOF_RESPONSE" | jq -r '.state_root')
    
    ACC_VERIFY=$(curl -s -X POST "$BASE_URL/verify/proof" \
      -H "Content-Type: application/json" \
      -d "{
        \"account\": $ACC_ACCOUNT,
        \"balance\": $ACC_BALANCE,
        \"proof\": \"$ACC_PROOF\",
        \"state_root\": \"$ACC_STATE_ROOT\"
      }")
    
    ACC_VALID=$(echo "$ACC_VERIFY" | jq -r '.valid')
    
    if [ "$ACC_VALID" == "true" ]; then
        echo -e "  ${GREEN}✓ Account $acc: Balance $ACC_BALANCE verified${NC}"
        ((MULTI_PASSED++))
    else
        echo -e "  ${RED}✗ Account $acc: Verification failed${NC}"
        ((MULTI_FAILED++))
    fi
done

if [ $MULTI_PASSED -gt 0 ]; then
    ((PASSED += MULTI_PASSED))
fi
if [ $MULTI_FAILED -gt 0 ]; then
    ((FAILED += MULTI_FAILED))
fi

# Test 5: Exclusion proof
print_test_header "Test 5: Exclusion Proof (Non-existent Account)"

echo "Testing exclusion proof for account 999 (should not exist)..."
EXCLUSION_RESPONSE=$(curl -s "$BASE_URL/proof/exclusion/999")

if echo "$EXCLUSION_RESPONSE" | jq -e '.proof' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Exclusion proof generated${NC}"
    echo "$EXCLUSION_RESPONSE" | jq '.'
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ Exclusion proof test skipped (account may exist or endpoint error)${NC}"
    echo "$EXCLUSION_RESPONSE"
fi

# Test 6: State root consistency
print_test_header "Test 6: State Root Consistency"

echo "Checking if state root matches across endpoints..."
ROOT1=$(curl -s "$BASE_URL/state-root" | jq -r '.state_root')
ROOT2=$(curl -s "$BASE_URL/proof/balance/0" | jq -r '.state_root')

if [ "$ROOT1" == "$ROOT2" ] && [ -n "$ROOT1" ] && [ "$ROOT1" != "null" ]; then
    echo -e "${GREEN}✓ State roots match: $ROOT1${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ State roots do not match${NC}"
    echo "  From /state-root: $ROOT1"
    echo "  From /proof/balance/0: $ROOT2"
    ((FAILED++))
fi

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}           Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Total Tests: $((PASSED + FAILED))"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    exit 1
fi
