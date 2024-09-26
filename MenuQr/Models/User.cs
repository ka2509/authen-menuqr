using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.ComponentModel.DataAnnotations;

namespace MenuQr.Models
{
    public class User
    {
        [BsonId]
        [BsonElement("_id"), BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; } 
        [BsonElement("first_name"), BsonRepresentation(BsonType.String)]
        public string FirstName { get; set; } = string.Empty;
        [BsonElement("last_name"), BsonRepresentation(BsonType.String)]
        public string LastName { get; set; } = string.Empty;
        [BsonElement("email"), BsonRepresentation(BsonType.String)]
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        [BsonElement("phone_number"), BsonRepresentation(BsonType.String)]
        public string PhoneNumber {  get; set; } = string.Empty;
        [BsonElement("refresh_token"), BsonRepresentation(BsonType.String)]
        public string? RefreshToken { get; set; }
        [BsonElement("refresh_token_expiry_time"), BsonRepresentation(BsonType.DateTime)]
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
