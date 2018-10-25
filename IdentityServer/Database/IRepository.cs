using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace IdentityServer
{
    public interface IRepository
    {
        void Add<T>(T item);

        Task AddAsync<T>(T item);

        void AddRange<T>(IEnumerable<T> list);

        Task AddRangeAsync<T>(IEnumerable<T> list);

        bool Any<T>();

        bool Any<T>(Expression<Func<T, bool>> where);

        Task<bool> AnyAsync<T>();

        Task<bool> AnyAsync<T>(Expression<Func<T, bool>> where);

        long Count<T>();

        long Count<T>(Expression<Func<T, bool>> where);

        Task<long> CountAsync<T>();

        Task<long> CountAsync<T>(Expression<Func<T, bool>> where);

        void Delete<T>(object key);

        void Delete<T>(Expression<Func<T, bool>> where);

        Task DeleteAsync<T>(object key);

        Task DeleteAsync<T>(Expression<Func<T, bool>> where);

        T FirstOrDefault<T>(Expression<Func<T, bool>> where);

        Task<T> FirstOrDefaultAsync<T>(Expression<Func<T, bool>> where);

        IEnumerable<T> List<T>();

        IEnumerable<T> List<T>(Expression<Func<T, bool>> where);

        Task<IEnumerable<T>> ListAsync<T>();

        Task<IEnumerable<T>> ListAsync<T>(Expression<Func<T, bool>> where);

        T Select<T>(object key);

        Task<T> SelectAsync<T>(object key);

        T SingleOrDefault<T>(Expression<Func<T, bool>> where);

        Task<T> SingleOrDefaultAsync<T>(Expression<Func<T, bool>> where);

        void Update<T>(T item, object key);

        Task UpdateAsync<T>(T item, object key);
    }
}
