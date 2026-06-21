// server.js - Add GET /api/admin/ledger

// Get all ledger entries (admin only)
app.get(
    "/api/admin/ledger",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {
        try {
            const { 
                limit = 50, 
                offset = 0, 
                status,
                user_id,
                start_date,
                end_date 
            } = req.query;

            // Build the query
            let query = supabase
                .from("account_ledger")
                .select(`
                    *,
                    user:users!account_ledger_user_id_fkey(
                        id,
                        name,
                        email,
                        account_number,
                        balance,
                        created_at as user_joined_at
                    )
                `)
                .order("created_at", { ascending: false });

            // Apply filters
            if (status) {
                query = query.eq("status", status);
            }

            if (user_id) {
                query = query.eq("user_id", user_id);
            }

            if (start_date) {
                query = query.gte("created_at", start_date);
            }

            if (end_date) {
                query = query.lte("created_at", end_date);
            }

            // Apply pagination
            const from = parseInt(offset);
            const to = from + parseInt(limit) - 1;
            query = query.range(from, to);

            const { data: ledgerEntries, error } = await query;

            if (error) {
                console.error("Admin ledger fetch error:", error);
                return res.status(500).json({
                    success: false,
                    message: "Failed to fetch ledger entries",
                    error: error.message,
                });
            }

            // Get total count
            let countQuery = supabase
                .from("account_ledger")
                .select("*", { count: "exact", head: true });

            if (status) {
                countQuery = countQuery.eq("status", status);
            }

            if (user_id) {
                countQuery = countQuery.eq("user_id", user_id);
            }

            if (start_date) {
                countQuery = countQuery.gte("created_at", start_date);
            }

            if (end_date) {
                countQuery = countQuery.lte("created_at", end_date);
            }

            const { count, error: countError } = await countQuery;

            if (countError) {
                console.error("Count error:", countError);
            }

            // Get summary statistics
            const { data: summaryData, error: summaryError } = await supabase
                .from("account_ledger")
                .select("status, difference")
                .eq("status", "flagged");

            let summary = {
                total_entries: count || 0,
                total_flagged: 0,
                total_matched: 0,
                total_discrepancy: 0,
            };

            if (!summaryError && summaryData) {
                summary.total_flagged = summaryData.filter(s => s.status === "flagged").length;
                summary.total_matched = summaryData.filter(s => s.status === "matched").length;
                
                // Calculate total discrepancy amount
                const flaggedEntries = summaryData.filter(s => s.status === "flagged");
                summary.total_discrepancy = flaggedEntries.reduce(
                    (sum, s) => sum + Math.abs(parseFloat(s.difference || 0)),
                    0
                );
            }

            // Format the response
            const formattedEntries = (ledgerEntries || []).map(entry => ({
                id: entry.id,
                user_id: entry.user_id,
                user: entry.user ? {
                    id: entry.user.id,
                    name: entry.user.name,
                    email: entry.user.email,
                    account_number: entry.user.account_number,
                    balance: parseFloat(entry.user.balance),
                    joined_at: entry.user.user_joined_at,
                } : null,
                ledger_balance: parseFloat(entry.ledger_balance),
                actual_balance: parseFloat(entry.actual_balance),
                difference: parseFloat(entry.difference),
                status: entry.status,
                flagged_reason: entry.flagged_reason,
                resolved_at: entry.resolved_at,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
            }));

            res.json({
                success: true,
                ledger: formattedEntries,
                total: count || 0,
                limit: parseInt(limit),
                offset: parseInt(offset),
                summary: summary,
            });

        } catch (error) {
            console.error("Admin ledger error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch ledger entries",
                error: error.message,
            });
        }
    },
);