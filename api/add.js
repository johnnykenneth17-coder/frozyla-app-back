// ===== MENU ROUTES =====
app.get("/api/menu", async (req, res) => {
  try {
    const { category } = req.query;
    let query = supabase.from("menu_items").select("*");

    if (category && category !== "all") {
      query = query.eq("category", category);
    }

    const { data, error } = await query.order("name");

    if (error) {
      console.error("Menu error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch menu",
        error: error.message
      });
    }

    // REMOVED: Mock data fallback - Now properly handles empty database
    if (!data || data.length === 0) {
      return res.json({ 
        success: true, 
        items: [],
        message: "No menu items found. Add items using the admin panel."
      });
    }

    res.json({ success: true, items: data });
  } catch (error) {
    console.error("Menu error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message
    });
  }
});