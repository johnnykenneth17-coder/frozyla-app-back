// server.js - Fixed updateUserBalance helper

async function updateUserBalance(
    userId,
    amount,
    transactionType,
    description,
    category,
    reference,
    orderId = null,
    fundingRequestId = null,
) {
    // Start a transaction
    const { data: user, error: userError } = await supabase
        .from("users")
        .select("balance")
        .eq("id", userId)
        .single();

    if (userError || !user) {
        throw new Error("User not found");
    }

    const balanceBefore = parseFloat(user.balance);
    const amountNum = parseFloat(amount);
    let balanceAfter;

    if (transactionType === "credit") {
        balanceAfter = balanceBefore + amountNum;
    } else if (transactionType === "debit") {
        if (balanceBefore < amountNum) {
            throw new Error("Insufficient balance");
        }
        balanceAfter = balanceBefore - amountNum;
    } else {
        throw new Error("Invalid transaction type");
    }

    // Update user balance
    const { error: updateError } = await supabase
        .from("users")
        .update({
            balance: balanceAfter,
            updated_at: new Date().toISOString(),
        })
        .eq("id", userId);

    if (updateError) throw updateError;

    // Create transaction record
    const transactionId = uuidv4();
    const transactionData = {
        id: transactionId,
        user_id: userId,
        transaction_type: transactionType,
        amount: amountNum,
        balance_before: balanceBefore,
        balance_after: balanceAfter,
        reference: reference || generateReference(),
        description: description,
        category: category,
        funding_request_id: fundingRequestId,
        status: "completed",
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
    };

    // ✅ Only add order_id if it exists and is valid
    if (orderId) {
        // Verify order exists before adding the reference
        const { data: orderCheck, error: orderCheckError } = await supabase
            .from("orders")
            .select("id")
            .eq("id", orderId)
            .single();

        if (!orderCheckError && orderCheck) {
            transactionData.order_id = orderId;
        } else {
            // Order doesn't exist, log warning but proceed without order_id
            console.warn(`Order ${orderId} not found, creating transaction without order reference`);
        }
    }

    const { error: txError } = await supabase
        .from("wallet_transactions")
        .insert([transactionData]);

    if (txError) throw txError;

    // Update account ledger
    await updateAccountLedger(userId);

    return { balanceBefore, balanceAfter, transactionId };
}