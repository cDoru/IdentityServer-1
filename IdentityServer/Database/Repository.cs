using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace IdentityServer
{
    public class Repository : IRepository
    {
        public Repository(IOptions<AppSettings> appSettings)
        {
            var connectionString = appSettings.Value.ConnectionStrings.IdentityServer;
            var settings = MongoClientSettings.FromUrl(new MongoUrl(connectionString));
            settings.SslSettings = new SslSettings { EnabledSslProtocols = SslProtocols.Tls12 };
            var mongoClient = new MongoClient(settings);
            Database = mongoClient.GetDatabase(nameof(appSettings.Value.ConnectionStrings.IdentityServer));
        }

        private IMongoDatabase Database { get; }

        public void Add<T>(T item)
        {
            Collection<T>().InsertOne(item);
        }

        public Task AddAsync<T>(T item)
        {
            return Collection<T>().InsertOneAsync(item);
        }

        public void AddRange<T>(IEnumerable<T> list)
        {
            Collection<T>().InsertMany(list);
        }

        public Task AddRangeAsync<T>(IEnumerable<T> list)
        {
            return Collection<T>().InsertManyAsync(list);
        }

        public bool Any<T>()
        {
            return Collection<T>().Find(new BsonDocument()).Any();
        }

        public bool Any<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().Find(where).Any();
        }

        public Task<bool> AnyAsync<T>()
        {
            return Collection<T>().Find(new BsonDocument()).AnyAsync();
        }

        public Task<bool> AnyAsync<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().Find(where).AnyAsync();
        }

        public long Count<T>()
        {
            return Collection<T>().CountDocuments(new BsonDocument());
        }

        public long Count<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().CountDocuments(where);
        }

        public Task<long> CountAsync<T>()
        {
            return Collection<T>().CountDocumentsAsync(new BsonDocument());
        }

        public Task<long> CountAsync<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().CountDocumentsAsync(where);
        }

        public void Delete<T>(object key)
        {
            Collection<T>().DeleteOne(FilterId<T>(key));
        }

        public void Delete<T>(Expression<Func<T, bool>> where)
        {
            Collection<T>().DeleteMany(where);
        }

        public Task DeleteAsync<T>(object key)
        {
            return Collection<T>().DeleteOneAsync(FilterId<T>(key));
        }

        public Task DeleteAsync<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().DeleteManyAsync(where);
        }

        public T FirstOrDefault<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().Find(where).FirstOrDefault();
        }

        public Task<T> FirstOrDefaultAsync<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().Find(where).FirstOrDefaultAsync();
        }

        public IEnumerable<T> List<T>()
        {
            return Collection<T>().Find(new BsonDocument()).ToList();
        }

        public IEnumerable<T> List<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().Find(where).ToList();
        }

        public async Task<IEnumerable<T>> ListAsync<T>(Expression<Func<T, bool>> where)
        {
            return await Collection<T>().Find(where).ToListAsync().ConfigureAwait(false);
        }

        public async Task<IEnumerable<T>> ListAsync<T>()
        {
            return await Collection<T>().Find(new BsonDocument()).ToListAsync().ConfigureAwait(false);
        }

        public T Select<T>(object key)
        {
            return Collection<T>().Find(FilterId<T>(key)).SingleOrDefault();
        }

        public Task<T> SelectAsync<T>(object key)
        {
            return Collection<T>().Find(FilterId<T>(key)).SingleOrDefaultAsync();
        }

        public T SingleOrDefault<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().Find(where).SingleOrDefault();
        }

        public Task<T> SingleOrDefaultAsync<T>(Expression<Func<T, bool>> where)
        {
            return Collection<T>().Find(where).SingleOrDefaultAsync();
        }

        public void Update<T>(T item, object key)
        {
            Collection<T>().ReplaceOne(FilterId<T>(key), item);
        }

        public Task UpdateAsync<T>(T item, object key)
        {
            return Collection<T>().ReplaceOneAsync(FilterId<T>(key), item);
        }

        private static FilterDefinition<T> FilterId<T>(object key)
        {
            return Builders<T>.Filter.Eq("Id", key);
        }

        private IMongoCollection<T> Collection<T>()
        {
            return Database.GetCollection<T>(typeof(T).Name);
        }
    }
}
