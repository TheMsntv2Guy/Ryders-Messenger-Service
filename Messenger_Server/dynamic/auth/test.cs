public static async Task ProcessRequest(HttpListenerContext context)
{
   // I really hope this works
    var response = context.Response;
    response.ContentType = "application/json";
    
    var result = new {
        status = "success",
        message = "It works bitch",
        time = DateTime.UtcNow
    };
    
    await response.OutputStream.WriteAsync(
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(result)));
}
