// server.js - Replace the admin funding requests endpoint

// Get all funding requests (admin)
app.get(
  "/api/admin/funding-requests",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { status, limit = 50, offset = 0 } = req.query;

      // Build the query with proper relationship aliases
      let query = supabase
        .from("card_funding_requests")
        .select(`
          *,
          user:users!card_funding_requests_user_id_fkey(
            id, 
            name, 
            email, 
            account_number, 
            balance
          ),
          card:payment_cards(
            card_number, 
            card_holder_name, 
            card_type
          ),
          approved_by_user:users!card_funding_requests_approved_by_fkey(
            id, 
            name, 
            email
          )
        `)
        .order("requested_at", { ascending: false });

      // Apply status filter
      if (status && status !== "all") {
        query = query.eq("status", status);
      }

      // Apply pagination
      if (limit) {
        query = query.range(
          parseInt(offset), 
          parseInt(offset) + parseInt(limit) - 1
        );
      }

      const { data: requests, error } = await query;

      if (error) {
        console.error("Admin funding requests error:", error);
        return res.status(500).json({
          success: false,
          message: "Failed to fetch funding requests",
          error: error.message,
        });
      }

      // Get total count for pagination
      let countQuery = supabase
        .from("card_funding_requests")
        .select("*", { count: "exact", head: true });

      if (status && status !== "all") {
        countQuery = countQuery.eq("status", status);
      }

      const { count, error: countError } = await countQuery;

      if (countError) {
        console.error("Count error:", countError);
      }

      // Mask card numbers for security
      const maskedRequests = (requests || []).map((req) => {
        // Create a copy to avoid mutating original
        const requestCopy = { ...req };
        
        if (requestCopy.card) {
          requestCopy.card = {
            ...requestCopy.card,
            card_number: requestCopy.card.card_number 
              ? requestCopy.card.card_number.replace(/\d(?=\d{4})/g, "*")
              : null,
          };
        }
        
        return requestCopy;
      });

      res.json({
        success: true,
        requests: maskedRequests || [],
        total: count || 0,
        limit: parseInt(limit),
        offset: parseInt(offset),
      });
    } catch (error) {
      console.error("Admin funding requests error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch funding requests",
        error: error.message,
      });
    }
  },
);