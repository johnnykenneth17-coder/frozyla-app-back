// server.js - Update the generateAccountNumber function

function generateAccountNumber() {
    // Generate a 10-digit number only (no letters)
    let accountNumber = '';
    for (let i = 0; i < 10; i++) {
        accountNumber += Math.floor(Math.random() * 10);
    }
    return accountNumber;
}

// Also update the user creation to use this function
// In signupUser function, add account number generation:
const accountNumber = generateAccountNumber();

// Update the users table insert to include account_number
const { data: user, error: createError } = await supabase
    .from("users")
    .insert([
        {
            id: userId,
            email: sanitizedEmail,
            password: hashedPassword,
            name: sanitizedName,
            role: "user",
            account_number: accountNumber, // Add this line
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
        },
    ])
    .select("id, email, name, role, account_number, created_at")
    .single();




    // server.js - Update get wallet balance endpoint
app.get("/api/wallet/balance", authMiddleware, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from("users")
            .select("balance, account_number, account_status")
            .eq("id", req.userId)
            .single();

        if (error || !user) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        // Ensure account number is properly returned
        const accountNumber = user.account_number || generateAccountNumber();
        
        // If account number is missing, update the user
        if (!user.account_number) {
            await supabase
                .from("users")
                .update({ account_number: accountNumber })
                .eq("id", req.userId);
        }

        res.json({
            success: true,
            balance: parseFloat(user.balance) || 0,
            account_number: accountNumber,
            account_status: user.account_status || "active",
        });
    } catch (error) {
        console.error("Wallet balance error:", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch balance",
        });
    }
});