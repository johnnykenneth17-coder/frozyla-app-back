// server.js - Add this endpoint

// Get user ledger balance (admin only)
app.get(
  "/api/admin/ledger/balance/:userId",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Get user info
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("id, name, email, account_number, balance")
        .eq("id", userId)
        .single();

      if (userError || !user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      // Get ledger balance from account_balances
      const { data: accountBalance, error: balanceError } = await supabase
        .from("account_balances")
        .select(`
          balance,
          total_debits,
          total_credits,
          updated_at,
          account:ledger_accounts(
            account_code,
            account_name
          )
        `)
        .eq("user_id", userId)
        .maybeSingle();

      if (balanceError) {
        console.error("Balance fetch error:", balanceError);
      }

      // Get recent transactions
      const { data: transactions, error: txError } = await supabase
        .from("wallet_transactions")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(20);

      if (txError) {
        console.error("Transactions fetch error:", txError);
      }

      // Get reconciliation status
      const { data: reconciliation, error: recError } = await supabase
        .from("ledger_reconciliation")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(1);

      if (recError) {
        console.error("Reconciliation fetch error:", recError);
      }

      const ledgerBalance = accountBalance ? {
        balance: parseFloat(accountBalance.balance || 0),
        total_debits: parseFloat(accountBalance.total_debits || 0),
        total_credits: parseFloat(accountBalance.total_credits || 0),
        updated_at: accountBalance.updated_at,
        account_code: accountBalance.account?.account_code,
        account_name: accountBalance.account?.account_name,
      } : {
        balance: 0,
        total_debits: 0,
        total_credits: 0,
        updated_at: null,
        account_code: null,
        account_name: null,
      };

      res.json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          account_number: user.account_number,
          balance: parseFloat(user.balance),
        },
        ledger_balance: ledgerBalance,
        transactions: (transactions || []).map(tx => ({
          id: tx.id,
          transaction_type: tx.transaction_type,
          amount: parseFloat(tx.amount),
          balance_before: parseFloat(tx.balance_before),
          balance_after: parseFloat(tx.balance_after),
          description: tx.description,
          reference: tx.reference,
          status: tx.status,
          created_at: tx.created_at,
        })),
        reconciliation: reconciliation && reconciliation.length > 0 ? {
          id: reconciliation[0].id,
          ledger_balance: parseFloat(reconciliation[0].ledger_balance),
          actual_balance: parseFloat(reconciliation[0].actual_balance),
          difference: parseFloat(reconciliation[0].difference),
          status: reconciliation[0].status,
          flagged_reason: reconciliation[0].flagged_reason,
          resolution_notes: reconciliation[0].resolution_notes,
          created_at: reconciliation[0].created_at,
          resolved_at: reconciliation[0].resolved_at,
        } : null,
      });

    } catch (error) {
      console.error("User ledger balance error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch user ledger balance",
        error: error.message,
      });
    }
  },
);